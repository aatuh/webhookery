package retry

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"time"
)

type Policy struct {
	MaxAttempts  int
	MaxDuration  time.Duration
	InitialDelay time.Duration
	MaxDelay     time.Duration
}

type Classification struct {
	Retryable bool
	Reason    string
}

func DefaultPolicy() Policy {
	return Policy{
		MaxAttempts:  12,
		MaxDuration:  72 * time.Hour,
		InitialDelay: 10 * time.Second,
		MaxDelay:     6 * time.Hour,
	}
}

func (p Policy) NextDelay(attempt int, rng *rand.Rand) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	capDelay := p.InitialDelay
	for i := 0; i < attempt; i++ {
		capDelay *= 2
		if capDelay >= p.MaxDelay {
			capDelay = p.MaxDelay
			break
		}
	}
	capDelay = minDuration(capDelay, p.MaxDelay)
	if capDelay <= 0 {
		return 0
	}
	if rng == nil {
		n, err := crand.Int(crand.Reader, big.NewInt(int64(capDelay)+1))
		if err != nil {
			return capDelay
		}
		return time.Duration(n.Int64())
	}
	return time.Duration(rng.Int63n(int64(capDelay) + 1))
}

func (p Policy) ClassifyStatus(status int) Classification {
	switch {
	case status >= 200 && status <= 299:
		return Classification{Retryable: false, Reason: "success"}
	case status == 408 || status == 409 || status == 425 || status == 429:
		return Classification{Retryable: true, Reason: "temporary_http"}
	case status >= 500 && status <= 599:
		return Classification{Retryable: true, Reason: "temporary_http"}
	default:
		return Classification{Retryable: false, Reason: "permanent_http"}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
