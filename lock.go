package certmagic_s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"path"
	"time"

	"github.com/minio/minio-go/v7"
	"go.uber.org/zap"
)

const (
	lockStaleInterval   = 2 * time.Minute
	lockRefreshInterval = 10 * time.Second
	lockPollInterval    = time.Second
	lockRequestTimeout  = 10 * time.Second
	maxLockRecordSize   = 4096
)

var errLockLost = errors.New("S3 lock ownership lost")

type s3Lock struct {
	owner     string
	etag      string
	active    bool
	unlocking bool
	cancel    context.CancelFunc
	done      chan struct{}
	released  chan struct{}
}

type lockRecord struct {
	Version  int    `json:"version"`
	Owner    string `json:"owner"`
	Nonce    string `json:"nonce"`
	Released bool   `json:"released"`
}

type lockObservation struct {
	etag  string
	since time.Time
}

func (s3 *S3) Lock(ctx context.Context, key string) error {
	name := s3.lockName(key)
	held, err := s3.reserveLock(ctx, name)
	if err != nil {
		return err
	}
	acquired := false
	defer func() {
		if !acquired {
			s3.forgetLock(name, held)
		}
	}()
	held.owner, err = randomLockToken()
	if err != nil {
		return err
	}
	var observed lockObservation
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		etag, err := s3.tryLock(ctx, name, held.owner, &observed)
		if err != nil {
			return fmt.Errorf("acquiring S3 lock %q: %w", key, err)
		}
		if etag != "" {
			if err := ctx.Err(); err != nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), lockRequestTimeout)
				_, releaseErr := s3.updateLock(cleanupCtx, name, held.owner, etag, true)
				cancel()
				if releaseErr != nil && !errors.Is(releaseErr, errLockLost) {
					s3.logger.Warn("releasing canceled S3 lock acquisition failed", zap.String("key", name), zap.Error(releaseErr))
				}
				return err
			}
			refreshCtx, cancel := context.WithCancel(context.Background())
			s3.locksMu.Lock()
			held.etag = etag
			held.cancel = cancel
			held.active = true
			s3.locksMu.Unlock()
			acquired = true
			go s3.refreshLock(refreshCtx, name, held)
			return nil
		}
		timer := time.NewTimer(lockPollInterval + time.Duration(mathrand.Int64N(int64(lockPollInterval/4))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s3 *S3) Unlock(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := s3.lockName(key)
	s3.locksMu.Lock()
	held := s3.locks[name]
	if held == nil || !held.active || held.unlocking {
		s3.locksMu.Unlock()
		return fmt.Errorf("releasing S3 lock %q: not held by this instance", key)
	}
	held.unlocking = true
	s3.locksMu.Unlock()
	released := false
	defer func() {
		if released {
			s3.forgetLock(name, held)
		} else {
			s3.locksMu.Lock()
			held.unlocking = false
			s3.locksMu.Unlock()
		}
	}()
	held.cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-held.done:
	}
	_, err := s3.updateLock(ctx, name, held.owner, held.etag, true)
	if errors.Is(err, errLockLost) {
		released = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("releasing S3 lock %q: %w", key, err)
	}
	released = true
	return nil
}

func (s3 *S3) reserveLock(ctx context.Context, name string) (*s3Lock, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s3.locksMu.Lock()
		if s3.locks == nil {
			s3.locks = make(map[string]*s3Lock)
		}
		held := s3.locks[name]
		if held == nil {
			held = &s3Lock{done: make(chan struct{}), released: make(chan struct{})}
			s3.locks[name] = held
			s3.locksMu.Unlock()
			return held, nil
		}
		s3.locksMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-held.released:
		}
	}
}

func (s3 *S3) forgetLock(name string, held *s3Lock) {
	s3.locksMu.Lock()
	defer s3.locksMu.Unlock()
	if s3.locks[name] == held {
		delete(s3.locks, name)
		close(held.released)
	}
}

func (s3 *S3) tryLock(ctx context.Context, name, owner string, observed *lockObservation) (string, error) {
	record, etag, err := s3.readLock(ctx, name)
	if err != nil && !isLockNotFound(err) {
		return "", err
	}
	if err == nil && !record.Released {
		if observed.etag != etag {
			observed.etag = etag
			observed.since = time.Now()
		}
		if time.Since(observed.since) < lockStaleInterval {
			return "", nil
		}
	}
	record, err = newLockRecord(owner, false)
	if err != nil {
		return "", err
	}
	updatedETag, err := s3.writeLock(ctx, name, record, etag)
	if err == nil {
		return updatedETag, nil
	}
	current, currentETag, readErr := s3.readLock(ctx, name)
	if readErr == nil && current == record {
		return currentETag, nil
	}
	if isLockConflict(err) || isLockNotFound(err) {
		return "", nil
	}
	return "", err
}

func (s3 *S3) refreshLock(ctx context.Context, name string, held *s3Lock) {
	defer close(held.done)
	ticker := time.NewTicker(lockRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		etag, err := s3.updateLock(ctx, name, held.owner, held.etag, false)
		if err == nil {
			held.etag = etag
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errLockLost) {
			s3.logger.Error("S3 lock lease lost while operation may still be running", zap.String("key", name), zap.Error(err))
			return
		}
		s3.logger.Warn("S3 lock lease refresh failed", zap.String("key", name), zap.Error(err))
	}
}

func (s3 *S3) updateLock(ctx context.Context, name, owner, etag string, released bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, lockRequestTimeout)
	defer cancel()
	var writeErr error
	for attempt := 0; attempt < 2; attempt++ {
		record, err := newLockRecord(owner, released)
		if err != nil {
			return "", err
		}
		updatedETag, err := s3.writeLock(ctx, name, record, etag)
		if err == nil {
			return updatedETag, nil
		}
		writeErr = err
		current, currentETag, readErr := s3.readLock(ctx, name)
		if isLockNotFound(readErr) {
			return "", errLockLost
		}
		if readErr != nil {
			return "", errors.Join(writeErr, readErr)
		}
		if current.Owner != owner || (current.Released && !released) {
			return "", errLockLost
		}
		if current == record || (current.Released && released) {
			return currentETag, nil
		}
		etag = currentETag
	}
	return "", writeErr
}

func (s3 *S3) readLock(ctx context.Context, name string) (lockRecord, string, error) {
	ctx, cancel := context.WithTimeout(ctx, lockRequestTimeout)
	defer cancel()
	object, err := s3.client.GetObject(ctx, s3.Bucket, name, minio.GetObjectOptions{})
	if err != nil {
		return lockRecord{}, "", err
	}
	defer object.Close()
	body, err := io.ReadAll(io.LimitReader(object, maxLockRecordSize+1))
	if err != nil {
		return lockRecord{}, "", err
	}
	if len(body) > maxLockRecordSize {
		return lockRecord{}, "", errors.New("S3 lock record is too large")
	}
	var record lockRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return lockRecord{}, "", fmt.Errorf("invalid S3 lock record: %w", err)
	}
	if record.Version != 1 || record.Owner == "" || record.Nonce == "" {
		return lockRecord{}, "", errors.New("invalid or unsupported S3 lock record")
	}
	info, err := object.Stat()
	if err != nil {
		return lockRecord{}, "", err
	}
	if info.ETag == "" {
		return lockRecord{}, "", errors.New("S3 lock object has no ETag")
	}
	return record, info.ETag, nil
}

func (s3 *S3) writeLock(ctx context.Context, name string, record lockRecord, etag string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, lockRequestTimeout)
	defer cancel()
	body, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	options := minio.PutObjectOptions{ContentType: "application/json", DisableMultipart: true}
	if etag == "" {
		options.SetMatchETagExcept("*")
	} else {
		options.SetMatchETag(etag)
	}
	info, err := s3.client.PutObject(ctx, s3.Bucket, name, bytes.NewReader(body), int64(len(body)), options)
	if err != nil {
		return "", err
	}
	if info.ETag == "" {
		return "", errors.New("S3 returned no ETag for lock write")
	}
	return info.ETag, nil
}

func (s3 *S3) lockName(key string) string {
	digest := sha256.Sum256([]byte(key))
	return s3.KeyPrefix(path.Join("locks", "s3-v1", hex.EncodeToString(digest[:])))
}

func newLockRecord(owner string, released bool) (lockRecord, error) {
	nonce, err := randomLockToken()
	return lockRecord{Version: 1, Owner: owner, Nonce: nonce, Released: released}, err
}

func randomLockToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func isLockConflict(err error) bool {
	response := minio.ToErrorResponse(err)
	return response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusConflict || response.Code == "PreconditionFailed" || response.Code == "ConditionalRequestConflict"
}

func isLockNotFound(err error) bool {
	response := minio.ToErrorResponse(err)
	return response.Code == "NoSuchKey" || (response.StatusCode == http.StatusNotFound && (response.Code == "NotFound" || response.Code == ""))
}
