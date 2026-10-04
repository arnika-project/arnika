package transport

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
)

func budgetCfg(interval, roundInterval, window time.Duration, pqc bool) *config.Config {
	return &config.Config{
		Interval:         interval,
		PQCRoundInterval: roundInterval,
		RateWindow:       window,
		PQCEnabled:       pqc,
	}
}

func TestRateBudget(t *testing.T) {
	const (
		attempts, pubKeyFrames, tagFrames = 3, 2, 1
		qkdPerInterval                    = attempts
		pqcPerRound                       = pubKeyFrames*attempts + tagFrames
	)
	cases := []struct {
		name                    string
		interval, round, window time.Duration
		pqc                     bool
		qkdEvents, pqcEvents    int
	}{
		{"defaults", 10 * time.Second, 10 * time.Second, time.Minute, true, 7, 8},
		{"five second interval", 5 * time.Second, 5 * time.Second, time.Minute, true, 13, 14},
		{"pqc disabled", 5 * time.Second, 5 * time.Second, time.Minute, false, 13, 0},
		{"independent cadences", 10 * time.Second, 120 * time.Second, time.Minute, true, 7, 2},
		{"ten second window", 5 * time.Second, 5 * time.Second, 10 * time.Second, true, 3, 4},
		{"sub second round interval floors to one round per second", 10 * time.Second, 500 * time.Millisecond, time.Minute, true, 7, 62},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.qkdEvents*qkdPerInterval + tc.pqcEvents*pqcPerRound
			if got := RateBudget(budgetCfg(tc.interval, tc.round, tc.window, tc.pqc)); got != want {
				t.Fatalf("RateBudget = %d, want %d", got, want)
			}
		})
	}
}

func TestRateBudgetAdmitsMaximumLegitimateTrafficAndNoMore(t *testing.T) {
	cfg := budgetCfg(5*time.Second, 5*time.Second, time.Minute, true)
	limit := RateBudget(cfg)

	limiter := newRateLimiter(limit, cfg.RateWindow)
	for i := 0; i < limit; i++ {
		if !limiter.Allow("10.0.0.1") {
			t.Fatalf("legitimate packet %d of %d was rate limited", i+1, limit)
		}
	}
	if limiter.Allow("10.0.0.1") {
		t.Fatal("the limiter admitted more than the calculated budget")
	}
}

func TestRateLimitIsPerSourceIP(t *testing.T) {
	limiter := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !limiter.Allow("10.0.0.1") {
			t.Fatalf("packet %d from the first IP was rejected inside its budget", i+1)
		}
	}
	if limiter.Allow("10.0.0.1") {
		t.Fatal("the first IP exceeded its budget without being rejected")
	}
	for i := 0; i < 3; i++ {
		if !limiter.Allow("10.0.0.2") {
			t.Fatalf("packet %d from the second IP was rejected; budgets are not per IP", i+1)
		}
	}
}

func TestEffectiveRateLimit(t *testing.T) {
	cfg := budgetCfg(5*time.Second, 5*time.Second, time.Minute, true)
	budget := RateBudget(cfg)

	t.Run("unset takes the calculated budget", func(t *testing.T) {
		cfg.RateLimit = 0
		limit, got, warning := EffectiveRateLimit(cfg)
		if limit != budget || got != budget {
			t.Fatalf("limit=%d budget=%d, want both %d", limit, got, budget)
		}
		if warning != "" {
			t.Fatalf("unexpected warning: %s", warning)
		}
	})

	t.Run("an explicit value at or above the budget is silent", func(t *testing.T) {
		cfg.RateLimit = budget + 100
		limit, _, warning := EffectiveRateLimit(cfg)
		if limit != budget+100 {
			t.Fatalf("limit = %d, want the override %d", limit, budget+100)
		}
		if warning != "" {
			t.Fatalf("unexpected warning: %s", warning)
		}
	})

	t.Run("an explicit value below the budget is kept and warned about", func(t *testing.T) {
		cfg.RateLimit = 30
		limit, got, warning := EffectiveRateLimit(cfg)
		if limit != 30 {
			t.Fatalf("limit = %d, want the override 30", limit)
		}
		if got != budget {
			t.Fatalf("budget = %d, want %d", got, budget)
		}
		for _, want := range []string{"30", fmt.Sprint(budget), "1m0s", "5s"} {
			if !strings.Contains(warning, want) {
				t.Fatalf("warning %q does not mention %q", warning, want)
			}
		}
	})

	t.Run("the warning says so when PQC is off", func(t *testing.T) {
		off := budgetCfg(5*time.Second, 5*time.Second, time.Minute, false)
		off.RateLimit = 1
		_, _, warning := EffectiveRateLimit(off)
		if !strings.Contains(warning, "disabled") {
			t.Fatalf("warning %q does not report PQC as disabled", warning)
		}
	})
}
