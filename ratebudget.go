package main

import (
	"fmt"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/pqchpke"
)

// The per-IP rate limiter runs before packet dispatch, so QKD and PQC traffic
// share one budget. A static default of 30 packets per minute was below what a
// healthy pair of peers exchanges at a five-second interval, so the limiter
// rejected legitimate frames. These two constants are what one protocol event
// contributes to that budget, both taken from the transport rather than
// restated, so a change to a retry count or a message size cannot leave the
// budget behind.
const (
	// qkdInboundPerInterval is what one QKD interval can legitimately deliver
	// to a listening socket: udpClient sends one DATA packet per attempt and
	// retries when no ACK arrives.
	qkdInboundPerInterval = udpClientMaxAttempts

	// pqcInboundPerRound is what one PQC round can legitimately deliver to the
	// responder's listening socket: the public key, whose whole message the
	// initiator retries when no reply arrives, plus the single-frame
	// confirmation tag.
	//
	// The responder's reply frames leave the listening socket rather than
	// arriving on it, and rate limiting applies only to inbound reads, so they
	// contribute nothing.
	pqcInboundPerRound = pqchpke.MessageFrames*pqchpke.MaxSendAttempts + 1
)

// eventsIn is the largest number of events spaced step apart that can fall
// inside a sliding window of length window.
//
// The +1 is not slack: a window of exactly n steps straddles n+1 boundaries
// depending on where it starts, and the limiter's window slides.
func eventsIn(window, step time.Duration) int {
	if step <= 0 || window <= 0 {
		return 0
	}
	return int(window/step) + 1
}

// rateBudget is the per-IP packet budget one legitimate peer needs inside
// RATE_WINDOW.
//
// It assumes the maximum inbound role allocation rather than an even split:
// roles are deterministic per interval but nothing makes them alternate, so one
// node can be BACKUP for every QKD interval and responder for every PQC round,
// taking the inbound side of both every time.
//
// The PQC term uses the scheduler's whole-second round spacing, not
// PQC_ROUND_INTERVAL itself, because the round index is second-granular.
func rateBudget(cfg *config.Config) int {
	n := eventsIn(cfg.RateWindow, cfg.Interval) * qkdInboundPerInterval
	if cfg.UsePQC() {
		spacing := time.Duration(pqchpke.RoundSeconds(cfg.PQCRoundInterval)) * time.Second
		// One round on top of the scheduled boundaries: Run serves the current
		// index immediately at startup, before the first boundary.
		n += (eventsIn(cfg.RateWindow, spacing) + 1) * pqcInboundPerRound
	}
	return n
}

// effectiveRateLimit resolves RATE_LIMIT against the calculated budget.
//
// An unset RATE_LIMIT (zero) takes the budget. An explicit value stays an
// operator override even when it is lower, because pre-authentication flood
// protection is exactly what an operator may want to tighten; a value below the
// budget returns a non-empty warning naming both numbers and the cadences that
// produced them, so the resulting drops are diagnosable.
func effectiveRateLimit(cfg *config.Config) (limit, budget int, warning string) {
	budget = rateBudget(cfg)
	if cfg.RateLimit == 0 {
		return budget, budget, ""
	}
	if cfg.RateLimit < budget {
		pqc := "disabled"
		if cfg.UsePQC() {
			pqc = cfg.PQCRoundInterval.String()
		}
		return cfg.RateLimit, budget, fmt.Sprintf(
			"RATE_LIMIT=%d is below the calculated legitimate budget of %d packets per source IP per RATE_WINDOW=%s (INTERVAL=%s, PQC_ROUND_INTERVAL=%s); legitimate QKD or PQC traffic can be rejected",
			cfg.RateLimit, budget, cfg.RateWindow, cfg.Interval, pqc)
	}
	return cfg.RateLimit, budget, ""
}
