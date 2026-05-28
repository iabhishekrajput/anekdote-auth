package redis

import (
	"context"
	"strings"

	"github.com/go-redis/redis/v8"
	"hash/fnv"
)

const (
	bloomRedisKey = "bloom:usernames"
	// bloomM: bit-array size. Sized for 100k users at ~1% false-positive rate.
	bloomM = 958506
	// bloomK: number of independent hash positions, derived from m/n * ln2.
	bloomK = 7
)

// UsernameBloom is a Redis-backed bit-array bloom filter for username lookups.
// MightExist returning false guarantees the username is not taken.
// MightExist returning true means "probably taken" — always confirm with the DB.
type UsernameBloom struct {
	client *redis.Client
}

// NewUsernameBloom creates a bloom filter backed by the given Redis client.
func NewUsernameBloom(client *redis.Client) *UsernameBloom {
	return &UsernameBloom{client: client}
}

// positions computes k bit positions for s using enhanced double hashing:
// h_i(x) = (h1(x) + i * h2(x)) % m.
// FNV-64a (h1) and FNV-64 (h2) give independent hash families.
func (b *UsernameBloom) positions(s string) [bloomK]uint64 {
	lower := strings.ToLower(s)

	h1 := fnv.New64a()
	h1.Write([]byte(lower))
	a := h1.Sum64()

	h2 := fnv.New64()
	h2.Write([]byte(lower))
	c := h2.Sum64()

	var pos [bloomK]uint64
	for i := uint64(0); i < bloomK; i++ {
		pos[i] = (a + i*c) % bloomM
	}
	return pos
}

// Add sets the k bits for username in the Redis bit array.
// Idempotent: safe to call for usernames already in the filter.
func (b *UsernameBloom) Add(ctx context.Context, username string) error {
	pipe := b.client.Pipeline()
	for _, p := range b.positions(username) {
		pipe.SetBit(ctx, bloomRedisKey, int64(p), 1)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// MightExist returns (false, nil) when the username is definitely not taken.
// Returns (true, nil) when the username is possibly taken (check the DB).
// Returns (true, err) on Redis failure — callers must fall back to the DB.
func (b *UsernameBloom) MightExist(ctx context.Context, username string) (bool, error) {
	pipe := b.client.Pipeline()
	cmds := make([]*redis.IntCmd, bloomK)
	for i, p := range b.positions(username) {
		cmds[i] = pipe.GetBit(ctx, bloomRedisKey, int64(p))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return true, err
	}
	for _, cmd := range cmds {
		if cmd.Val() == 0 {
			return false, nil
		}
	}
	return true, nil
}

// LoadAll populates the filter from a list of existing usernames.
// Uses a single pipelined batch; safe to call at startup.
func (b *UsernameBloom) LoadAll(ctx context.Context, usernames []string) error {
	if len(usernames) == 0 {
		return nil
	}
	pipe := b.client.Pipeline()
	for _, u := range usernames {
		for _, p := range b.positions(u) {
			pipe.SetBit(ctx, bloomRedisKey, int64(p), 1)
		}
	}
	_, err := pipe.Exec(ctx)
	return err
}
