package certmagic_s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

var (
	// implementing these interfaces
	_ caddy.Module          = (*S3)(nil)
	_ certmagic.Storage     = (*S3)(nil)
	_ certmagic.Locker      = (*S3)(nil)
	_ caddy.Provisioner     = (*S3)(nil)
	_ caddyfile.Unmarshaler = (*S3)(nil)
)

func init() {
	caddy.RegisterModule(&S3{})
}

type S3 struct {
	logger *zap.Logger
	client *minio.Client

	// locks tracks the locks this process currently holds, keyed by the S3 lock
	// object key. Each entry carries the acquisition token (so Unlock only
	// deletes a lock we still own) and a cancel func to stop its heartbeat.
	// Guarded by locksMu.
	locksMu sync.Mutex
	locks   map[string]*heldLock

	// S3 configuration
	Host           string `json:"host"`
	Bucket         string `json:"bucket"`
	AccessID       string `json:"access_id"`
	SecretKey      string `json:"secret_key"`
	Prefix         string `json:"prefix,omitempty"`
	Insecure       bool   `json:"insecure"`
	UseIamProvider bool   `json:"use_iam_provider"`
}

const (
	// lockExpiration is how long a lock may go without a heartbeat refresh
	// before another process treats the holder as dead and steals it. Because a
	// live holder refreshes its lock every lockRefreshInterval, this does NOT
	// need to cover worst-case issuance time: a live holder is never stolen no
	// matter how long ACME/backoff takes, and only a crashed holder (whose
	// heartbeat stopped) is reclaimed, within roughly lockExpiration.
	lockExpiration = 60 * time.Second

	// lockRefreshInterval is how often a holder rewrites its lock object to
	// prove liveness. It must be comfortably smaller than lockExpiration so a
	// couple of missed refreshes (a transient S3 blip) don't cause a false
	// steal of a still-live lock.
	lockRefreshInterval = 20 * time.Second

	// lockPollInterval is how long a waiter sleeps between attempts when the
	// lock for the same name is currently held by someone else.
	lockPollInterval = 1 * time.Second

	// lockMaxLifetime caps how long the heartbeat keeps refreshing a single
	// lock. It is a safety net against a leaked lock (Unlock never called)
	// pinning a domain forever: after this the heartbeat stops, the lock goes
	// stale, and it becomes stealable.
	lockMaxLifetime = 10 * time.Minute
)

// heldLock is the bookkeeping for a lock this process currently holds.
type heldLock struct {
	token  string
	cancel context.CancelFunc
	done   chan struct{}
}

func (s3 *S3) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {

		key := d.Val()

		var value string
		if !d.Args(&value) {
			continue
		}

		switch key {
		case "host":
			s3.Host = value
			err := validateHost(s3.Host)
			if err != nil {
				return d.Err("Invalid usage of host in s3-storage config: " + err.Error())
			}
		case "bucket":
			s3.Bucket = value
		case "access_id":
			s3.AccessID = value
		case "secret_key":
			s3.SecretKey = value
		case "prefix":
			s3.Prefix = value
		case "insecure":
			insecure, err := strconv.ParseBool(value)
			if err != nil {
				return d.Err("Invalid usage of insecure in s3-storage config: " + err.Error())
			}
			s3.Insecure = insecure
		case "use_iam_provider":
			boolValue, err := strconv.ParseBool(value)
			if err != nil {
				return d.Err("Invalid usage of use_iam_provider in s3-storage config: " + err.Error())
			}
			s3.UseIamProvider = boolValue
		}

	}

	return nil
}

func (s3 *S3) Provision(ctx caddy.Context) error {
	s3.logger = ctx.Logger(s3)

	// Load Environment
	if s3.Host == "" {
		s3.Host = os.Getenv("S3_HOST")
	}

	err := validateHost(s3.Host)
	if err != nil {
		return err
	}

	if !s3.UseIamProvider {
		boolVal := os.Getenv("S3_USE_IAM_PROVIDER")
		if boolVal != "" {
			s3.UseIamProvider, err = strconv.ParseBool(boolVal)

			if err != nil {
				s3.UseIamProvider = false // default value
			}
		}
	}

	if s3.Bucket == "" {
		s3.Bucket = os.Getenv("S3_BUCKET")
		if s3.Bucket == "" {
			return errors.New("bucket is empty")
		}
	}

	if s3.AccessID == "" {
		s3.AccessID = os.Getenv("S3_ACCESS_ID")
		if s3.AccessID == "" && !s3.UseIamProvider {
			return errors.New("access_id is empty and use_iam_provider is false")
		}
	}

	if s3.SecretKey == "" {
		s3.SecretKey = os.Getenv("S3_SECRET_KEY")
		if s3.SecretKey == "" && !s3.UseIamProvider {
			return errors.New("secret_key is empty and use_iam_provider is false")
		}
	}

	if s3.Prefix == "" {
		s3.Prefix = os.Getenv("S3_PREFIX")
	}

	if !s3.Insecure {
		insecure := os.Getenv("S3_INSECURE")
		if insecure != "" {
			s3.Insecure, err = strconv.ParseBool(insecure)

			if err != nil {
				s3.Insecure = false // default value
			}
		}
	}
	secure := !s3.Insecure

	var creds *credentials.Credentials
	if s3.UseIamProvider {
		s3.logger.Info("using iam aws provider for credentials")
		creds = credentials.NewIAM("")
	} else {
		s3.logger.Info("using secret_key and access_id for credentials")
		creds = credentials.NewStaticV4(s3.AccessID, s3.SecretKey, "")
	}

	// S3 Client
	client, err := minio.New(s3.Host, &minio.Options{
		Creds:  creds,
		Secure: secure,
	})
	if err != nil {
		return err
	}

	s3.client = client
	s3.locks = make(map[string]*heldLock)
	return nil
}

func (*S3) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.s3",
		New: func() caddy.Module {
			return &S3{}
		},
	}
}

func (s3 *S3) CertMagicStorage() (certmagic.Storage, error) {
	return s3, nil
}

// Lock implements a distributed lock backed by S3 so certificate issuance is
// serialized and deduplicated across goroutines AND across instances. Without
// it, concurrent requests for the same domain each fire their own ACME order,
// which is what overwhelms the CA on cold start.
//
// Acquisition is atomic: PutObject with If-None-Match: * (via SetMatchETagExcept)
// creates the lock object only if it does not already exist, so exactly one
// caller wins even under a race; everyone else gets 412 PreconditionFailed and
// waits. Once held, a heartbeat refreshes the lock every lockRefreshInterval so
// a live holder is never stolen regardless of how long issuance takes; only a
// crashed holder (heartbeat stopped) goes stale and is stolen after
// lockExpiration. Honors ctx cancellation.
func (s3 *S3) Lock(ctx context.Context, key string) error {
	lockKey := s3.LockKey(key)
	token, err := newLockToken()
	if err != nil {
		s3.logger.Error("lock token generation failed", zap.String("key", lockKey), zap.Error(err))
		return err
	}

	for {
		err := s3.tryAcquireLock(ctx, lockKey, token)
		if err == nil {
			s3.startHeartbeat(lockKey, token)
			s3.logger.Debug("lock acquired", zap.String("key", lockKey))
			return nil
		}

		if !isPreconditionFailed(err) {
			// A throttle/network/permission error here (not "lock already
			// held") means we could not even attempt the lock. Surface it so a
			// storage outage isn't silently swallowed into unserialized issuance.
			s3.logger.Error("lock acquire failed",
				zap.String("key", lockKey),
				zap.String("s3_error_code", s3ErrorCode(err)),
				zap.Error(err))
			return err
		}

		// The lock is held. Steal it if it has expired, otherwise wait.
		if info, serr := s3.client.StatObject(ctx, s3.Bucket, lockKey, minio.StatObjectOptions{}); serr == nil {
			if time.Since(info.LastModified) > lockExpiration {
				s3.logger.Warn("stealing expired lock",
					zap.String("key", lockKey),
					zap.Time("acquired_at", info.LastModified))
				if rerr := s3.client.RemoveObject(ctx, s3.Bucket, lockKey, minio.RemoveObjectOptions{}); rerr != nil {
					s3.logger.Error("failed to remove expired lock",
						zap.String("key", lockKey),
						zap.String("s3_error_code", s3ErrorCode(rerr)),
						zap.Error(rerr))
				}
				continue
			}
		}

		select {
		case <-time.After(lockPollInterval):
		case <-ctx.Done():
			s3.logger.Debug("lock wait canceled", zap.String("key", lockKey), zap.Error(ctx.Err()))
			return ctx.Err()
		}
	}
}

// Unlock releases a lock previously acquired by this process. It stops the
// heartbeat first, then deletes the lock object only if we still own it (the
// stored token still matches ours), so we never delete a lock that was stolen
// from us after expiry and re-acquired by someone else.
func (s3 *S3) Unlock(ctx context.Context, key string) error {
	lockKey := s3.LockKey(key)

	s3.locksMu.Lock()
	held, ok := s3.locks[lockKey]
	delete(s3.locks, lockKey)
	s3.locksMu.Unlock()

	if !ok {
		s3.logger.Debug("unlock called for a lock we do not track; skipping delete", zap.String("key", lockKey))
		return nil
	}

	// Stop the heartbeat and wait for it to exit before deleting, so an
	// in-flight refresh can't recreate the object right after we remove it.
	held.cancel()
	<-held.done

	if current, err := s3.readLockToken(ctx, lockKey); err == nil && current != held.token {
		s3.logger.Warn("lock no longer owned by us; not deleting", zap.String("key", lockKey))
		return nil
	}

	if err := s3.client.RemoveObject(ctx, s3.Bucket, lockKey, minio.RemoveObjectOptions{}); err != nil {
		s3.logger.Error("unlock failed",
			zap.String("key", lockKey),
			zap.String("s3_error_code", s3ErrorCode(err)),
			zap.Error(err))
		return err
	}

	s3.logger.Debug("lock released", zap.String("key", lockKey))
	return nil
}

// startHeartbeat records the held lock and launches a goroutine that keeps its
// lock object fresh until Unlock (or lockMaxLifetime) stops it.
func (s3 *S3) startHeartbeat(lockKey, token string) {
	hbCtx, cancel := context.WithTimeout(context.Background(), lockMaxLifetime)
	done := make(chan struct{})

	s3.locksMu.Lock()
	s3.locks[lockKey] = &heldLock{token: token, cancel: cancel, done: done}
	s3.locksMu.Unlock()

	go s3.refreshLock(hbCtx, lockKey, token, done)
}

// refreshLock rewrites the lock object every lockRefreshInterval to prove the
// holder is still alive, so the lock's age never crosses lockExpiration while
// we hold it. It refreshes only while we still own the lock, so it never
// resurrects a lock that was legitimately stolen and released by someone else.
func (s3 *S3) refreshLock(ctx context.Context, lockKey, token string, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(lockRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := s3.readLockToken(ctx, lockKey)
			if err != nil {
				if isNotExist(err) {
					s3.logger.Warn("held lock disappeared; stopping heartbeat", zap.String("key", lockKey))
					return
				}
				// A transient read error: skip this refresh rather than risk
				// clobbering a newer owner. If it persists, our lock will go
				// stale and be stolen, which is the correct outcome when S3 is
				// unhealthy.
				s3.logger.Warn("lock heartbeat read failed; skipping refresh",
					zap.String("key", lockKey),
					zap.String("s3_error_code", s3ErrorCode(err)),
					zap.Error(err))
				continue
			}
			if current != token {
				s3.logger.Warn("held lock was stolen; stopping heartbeat", zap.String("key", lockKey))
				return
			}

			body := []byte(token)
			if _, err := s3.client.PutObject(ctx, s3.Bucket, lockKey, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{ContentType: "text/plain"}); err != nil {
				s3.logger.Warn("lock heartbeat refresh failed",
					zap.String("key", lockKey),
					zap.String("s3_error_code", s3ErrorCode(err)),
					zap.Error(err))
			}
		}
	}
}

// tryAcquireLock attempts to atomically create the lock object. If-None-Match: *
// makes S3 reject the write (412 PreconditionFailed) when the object already
// exists, so only one concurrent caller can succeed.
func (s3 *S3) tryAcquireLock(ctx context.Context, lockKey, token string) error {
	opts := minio.PutObjectOptions{ContentType: "text/plain"}
	opts.SetMatchETagExcept("*")

	body := []byte(token)
	_, err := s3.client.PutObject(ctx, s3.Bucket, lockKey, bytes.NewReader(body), int64(len(body)), opts)
	return err
}

// readLockToken returns the token currently stored in the lock object.
func (s3 *S3) readLockToken(ctx context.Context, lockKey string) (string, error) {
	object, err := s3.client.GetObject(ctx, s3.Bucket, lockKey, minio.GetObjectOptions{})
	if err != nil {
		return "", err
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LockKey maps a certmagic lock name to a dedicated S3 key namespace, kept
// separate from stored data so lock objects never show up in List of certs.
func (s3 *S3) LockKey(key string) string {
	return s3.KeyPrefix(path.Join("locks", key+".lock"))
}

// newLockToken returns a random token that uniquely identifies one acquisition,
// used to prove ownership on Unlock.
func newLockToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// isPreconditionFailed reports whether err is S3's 412 response, i.e. the lock
// object already existed and our atomic create was rejected.
func isPreconditionFailed(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.StatusCode == http.StatusPreconditionFailed || resp.Code == "PreconditionFailed"
}

func (s3 *S3) Store(ctx context.Context, key string, value []byte) error {
	key = s3.KeyPrefix(key)
	length := int64(len(value))

	s3.logger.Debug("store", zap.String("key", key), zap.Int64("bytes", length))

	_, err := s3.client.PutObject(ctx, s3.Bucket, key, bytes.NewReader(value), length, minio.PutObjectOptions{})
	if err != nil {
		s3.logger.Error("store failed",
			zap.String("key", key),
			zap.Int64("bytes", length),
			zap.String("s3_error_code", s3ErrorCode(err)),
			zap.Error(err))
	}

	return err
}

func (s3 *S3) Load(ctx context.Context, key string) ([]byte, error) {
	if !s3.Exists(ctx, key) {
		return nil, fs.ErrNotExist
	}

	key = s3.KeyPrefix(key)

	s3.logger.Debug("load", zap.String("key", key))

	object, err := s3.client.GetObject(ctx, s3.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		s3.logger.Error("load failed",
			zap.String("key", key),
			zap.String("s3_error_code", s3ErrorCode(err)),
			zap.Error(err))
		return nil, err
	}
	defer object.Close()

	// minio's GetObject is lazy: transport, throttling and not-found errors
	// surface here on the first read rather than from GetObject above.
	data, err := io.ReadAll(object)
	if err != nil {
		s3.logger.Error("load read failed",
			zap.String("key", key),
			zap.String("s3_error_code", s3ErrorCode(err)),
			zap.Error(err))
		return nil, err
	}

	return data, nil
}

func (s3 *S3) Delete(ctx context.Context, key string) error {
	key = s3.KeyPrefix(key)

	s3.logger.Debug("delete", zap.String("key", key))

	err := s3.client.RemoveObject(ctx, s3.Bucket, key, minio.RemoveObjectOptions{})
	if err != nil {
		s3.logger.Error("delete failed",
			zap.String("key", key),
			zap.String("s3_error_code", s3ErrorCode(err)),
			zap.Error(err))
	}

	return err
}

func (s3 *S3) Exists(ctx context.Context, key string) bool {
	key = s3.KeyPrefix(key)

	_, err := s3.client.StatObject(ctx, s3.Bucket, key, minio.StatObjectOptions{})
	if err == nil {
		s3.logger.Debug("exists", zap.String("key", key), zap.Bool("exists", true))
		return true
	}

	if isNotExist(err) {
		s3.logger.Debug("exists", zap.String("key", key), zap.Bool("exists", false))
		return false
	}

	// A non-404 failure (throttling, network, permissions) is reported to
	// certmagic as "does not exist", which makes it request a fresh cert from
	// the CA even though one may already be cached in S3. This is how an S3
	// overload turns into a CA stampede, so log it loudly and tag the S3 code
	// (e.g. SlowDown, RequestLimitExceeded) to confirm throttling from logs.
	s3.logger.Error("exists check failed; treating as not-exist, which may trigger a spurious CA request",
		zap.String("key", key),
		zap.String("s3_error_code", s3ErrorCode(err)),
		zap.Error(err))

	return false
}

func (s3 *S3) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	prefix = s3.KeyPrefix(prefix)

	objects := s3.client.ListObjects(ctx, s3.Bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: recursive,
	})

	// Start empty and append: len() on the results channel is its buffered
	// count, not the number of objects, so make([]string, len(objects)) would
	// prepend blank entries.
	keys := make([]string, 0)

	for object := range objects {
		if object.Err != nil {
			s3.logger.Error("list failed",
				zap.String("prefix", prefix),
				zap.String("s3_error_code", s3ErrorCode(object.Err)),
				zap.Error(object.Err))
			return keys, object.Err
		}
		keys = append(keys, s3.CutKeyPrefix(object.Key))
	}

	return keys, nil
}

func (s3 *S3) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	key = s3.KeyPrefix(key)

	object, err := s3.client.StatObject(ctx, s3.Bucket, key, minio.StatObjectOptions{})

	if err != nil {
		s3.logger.Error("stat failed",
			zap.String("key", key),
			zap.String("s3_error_code", s3ErrorCode(err)),
			zap.Error(err))

		return certmagic.KeyInfo{}, nil
	}

	s3.logger.Debug("stat", zap.String("key", key), zap.Int64("bytes", object.Size))

	return certmagic.KeyInfo{
		Key:        object.Key,
		Modified:   object.LastModified,
		Size:       object.Size,
		IsTerminal: strings.HasSuffix(object.Key, "/"),
	}, err
}

// s3ErrorCode extracts the S3/minio error code (e.g. "NoSuchKey", "SlowDown",
// "RequestLimitExceeded") when available. Throttling surfaces here as
// "SlowDown" or "RequestLimitExceeded" — the signal to look for when S3 is the
// bottleneck. Returns "" for non-S3 errors (e.g. transport failures).
func s3ErrorCode(err error) string {
	return minio.ToErrorResponse(err).Code
}

// isNotExist reports whether err is a genuine "object not found" response, as
// opposed to a transport, throttling or permission error that merely looks
// like absence to a naive err != nil check.
func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	resp := minio.ToErrorResponse(err)
	return resp.StatusCode == http.StatusNotFound || resp.Code == "NoSuchKey"
}

func (s3 *S3) KeyPrefix(key string) string {
	return path.Join(s3.Prefix, key)
}
func (s3 *S3) CutKeyPrefix(key string) string {
	cutted, _ := strings.CutPrefix(key, s3.Prefix)
	return cutted
}

func (s3 *S3) String() string {
	return fmt.Sprintf("S3 Storage Host: %s, Bucket: %s, Prefix: %s", s3.Host, s3.Bucket, s3.Prefix)
}

func validateHost(h string) error {
	u, err := url.Parse(h)
	if err != nil {
		return fmt.Errorf("invalid host: must be a hostname: %w", err)
	}
	if u.Scheme != "" {
		return errors.New("host must not contain a scheme prefix like https://")
	}
	return nil
}
