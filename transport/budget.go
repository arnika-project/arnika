package transport

import (
	"fmt"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories/pqchpke"
)

const (
	qkdInboundPerInterval = udpClientMaxAttempts
	pqcInboundPerRound    = pqchpke.MessageFrames*pqchpke.MaxSendAttempts + 1 // +1 is the confirmation tag; replies are outbound and not rate limited
)

// eventsIn is the most events spaced step apart inside a sliding window: n steps can straddle n+1 events.
func eventsIn(window, step time.Duration) int {
	if step <= 0 || window <= 0 {
		return 0
	}
	return int(window/step) + 1
}

// RateBudget assumes this node is inbound for every interval and round, since roles need not alternate, plus the round Run serves at startup.
func RateBudget(cfg *config.Config) int {
	n := eventsIn(cfg.RateWindow, cfg.Interval) * qkdInboundPerInterval
	if cfg.UsePQC() {
		spacing := time.Duration(pqchpke.RoundSeconds(cfg.PQCRoundInterval)) * time.Second
		n += (eventsIn(cfg.RateWindow, spacing) + 1) * pqcInboundPerRound
	}
	return n
}

// EffectiveRateLimit honours an explicit RATE_LIMIT even below the budget, since tightening flood protection is the operator's call, and warns.
func EffectiveRateLimit(cfg *config.Config) (limit, budget int, warning string) {
	budget = RateBudget(cfg)
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
