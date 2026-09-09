package main

import (
	"sync"
	"time"
)

// rateLimiter implements a simple per-IP rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go func() {
		for {
			time.Sleep(window)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	times := rl.requests[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for ip, times := range rl.requests {
		valid := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// logThrottle emits at most one message per interval.
//
// Packet-level warnings are driven by whatever arrives on the socket, so an
// unthrottled one lets flood or malformed traffic turn logging into a denial of
// service. The zero value allows every call, which is the safe default for a
// caller that forgets to set an interval.
//
// Not safe for concurrent use: every user is the UDP read loop, a single
// goroutine, and a mutex here would be pure ceremony.
type logThrottle struct {
	interval time.Duration
	next     time.Time
}

func (t *logThrottle) allow() bool {
	now := time.Now()
	if now.Before(t.next) {
		return false
	}
	t.next = now.Add(t.interval)
	return true
}
