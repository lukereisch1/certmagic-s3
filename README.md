# CertMagic-S3

CertMagic S3-compatible driver written in Go.

## Distributed locking

`Lock` and `Unlock` coordinate CertMagic jobs (certificate issuance and renewal,
ACME account registration, renewal-information updates, and storage cleanup)
across instances using the same bucket and prefix. They are exclusive named
mutexes, not reader/writer locks around individual `Load` and `Store` calls.
Storage operations retain their existing behavior and do not acquire these locks
internally.

### Backend requirements and algorithm

- Requires strongly consistent object reads and atomic conditional `PutObject`
  support for both `If-None-Match: *` and `If-Match: <ETag>`. AWS S3 general-purpose
  buckets support these operations. An S3-compatible endpoint must implement and
  enforce both conditions; do not use a backend that silently ignores them.
- Creates small versioned JSON records under
  `<prefix>/locks/s3-v1/<sha256-of-lock-name>`. Acquisition uses conditional create
  or ETag compare-and-swap, never check-then-unconditional-write.
- Each acquisition has a cryptographically random owner token. Every write also
  has a fresh random nonce so that released records and heartbeat writes cannot
  reuse an old content-based ETag.
- Refreshes a held lease every 10 seconds using conditional writes. A contender
  may replace a record only after observing its ETag unchanged for two minutes
  on its own monotonic clock. Recovery therefore takes at least two minutes
  from the contender's first observation; machine clock differences and object
  timestamps do not make a live lock prematurely stale.
- Releases with an ETag-conditional write marking the record released, not a
  delete. The pinned MinIO Go SDK does not expose conditional delete, and an
  unconditional delete could erase a successor's lock. One small reusable
  released record remains per distinct lock name; no bucket versioning or extra
  service is required.
- Resolves ambiguous write responses by reading back the owner and nonce before
  accepting success or retrying. Requests have a 10-second timeout. Acquisition
  respects context cancellation, while heartbeats deliberately survive the
  acquisition context until `Unlock`, as required by CertMagic's contract.
- Polls contended remote locks roughly once per second with jitter. Different
  names remain independent. Calls for the same name on one storage instance are
  serialized locally, including when its remote lease has been lost.

The existing S3 `GetObject` and `PutObject` permissions must cover this prefix.
This is unrelated to AWS **S3 Object Lock** (WORM retention), which must not prevent
the lock records from being overwritten.

### Failure handling and limitations

This is a renewable lease, not a fencing-token protocol for the certificate
objects or the CA. A process paused or partitioned for longer than the stale
interval can continue its original work after another instance takes over.
CertMagic's lock interface cannot cancel that operation or fence its writes;
it explicitly permits rare timeout-based mis-synchronization. Conditional writes
protect the lock record itself: a former owner cannot refresh or release its
successor's lease. Ownership loss and renewal failures are logged.

Call `Unlock` after every successful `Lock`, even if the operation's context was
canceled; use a fresh context for cleanup. An already-canceled `Unlock` leaves
the lease running. If an attempted release fails, its renewal stops and the
local reservation remains until a successful `Unlock` retry or process restart,
so a retry cannot accidentally release a newer same-instance holder. Other
instances can recover the stale lease. Monitor release failures: CertMagic may
log rather than immediately retry them. Unknown outcomes after an acquisition
timeout can similarly leave a record for stale recovery. Malformed records and
permission/backend errors fail closed instead of being treated as free locks.

Do not expire or externally delete active lock records. In particular, remove
blanket lifecycle expiration from a certificate bucket: it can delete valid
certificate/key objects independently of this locking change. Released lock
records are intentionally retained and reused. On a versioned bucket, heartbeats
create noncurrent versions; use a policy targeting noncurrent versions only if
needed, never a blanket current-object expiry policy.

### Rollout

Build a new Caddy image pinned to the reviewed module revision, test it against
an isolated preproduction bucket on the actual storage backend, then replace
all instances sharing the production bucket/prefix. Existing certificate and
account object formats are unchanged. No S3 migration, new IAM service, or bucket
replacement is needed; permissions must include the new lock prefix.

Older versions of this fork have no-op locks and do not participate in this
protocol. A mixed-version rolling deployment is **not fully protected** until
all old instances have stopped; drain or stop old issuers before relying on
exclusivity. Rolling back to a no-op version removes that protection. This does
not restore already-deleted certificates or solve unrelated false-miss behavior
in `Exists`/`Load`.

### Design references and alternatives

- [CertMagic v0.23.0 Storage/Locker contract](https://github.com/caddyserver/certmagic/blob/v0.23.0/storage.go)
  separates job-level locking from storage reads/writes and permits renewable
  leases when fencing is unavailable.
- [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
  specify atomic create/CAS semantics and conflict responses.
- [techknowlogick/certmagic-s3 locking](https://github.com/techknowlogick/certmagic-s3/blob/6c26852bb192f1f0ccfe36b0508b3b9f12116632/lock.go)
  uses conditional creation, heartbeat refresh, stale takeover and conditional
  deletion with the AWS SDK. Adopting that package would also change the SDK and
  storage/configuration implementation; this fork keeps its current dependencies
  and uses conditional release records instead.
- [Terraform's S3 lockfile](https://github.com/hashicorp/terraform/blob/main/internal/backend/remote-state/s3/client.go)
  uses conditional creation, but its operator-driven lock recovery is not a fit
  for unattended CertMagic jobs. DynamoDB-backed locks would add a service, IAM
  permissions and operational dependencies without enabling end-to-end fencing
  through the existing CertMagic interface.
- [AWS conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html)
  could replace release records in a future SDK/backend compatibility change;
  this implementation never falls back to unsafe unconditional deletion.

## Guide

Build

    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

    xcaddy build --output ./caddy --with github.com/ss098/certmagic-s3

Build container

    FROM caddy:builder AS builder
    RUN xcaddy build --with github.com/ss098/certmagic-s3 --with ...

    FROM caddy
    COPY --from=builder /usr/bin/caddy /usr/bin/caddy

Run

    caddy run --config caddy.json

Caddyfile Example

    # Global Config

    {
        storage s3 {
            host "s3.example.com"
            bucket "my-cert-bucket"
            access_id "Access ID"
            secret_key "Secret Key"
            prefix "ssl"
            insecure false #disables SSL if true
        }
    }

JSON Config Example

    {
      "storage": {
        "module": "s3",
        "host": "s3.example.com",
        "bucket": "my-cert-bucket",
        "access_id": "Access ID",
        "secret_key": "Secret Key",
        "prefix": "ssl",
        "insecure": false
      }
      "app": {
        ...
      }
    }

From Environment

    S3_HOST
    S3_BUCKET
    S3_ACCESS_ID
    S3_SECRET_KEY
    S3_PREFIX
    S3_INSECURE

AWS IAM Provider Example

Caddyfile Example

    # Global Config

    {
        storage s3 {
            host "s3.example.com"
            bucket "my-cert-bucket"
            use_iam_provider true
            prefix "ssl"
            insecure false #disables SSL if true
        }
    }
