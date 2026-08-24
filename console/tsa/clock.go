package tsa

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Moment is the UTC time and conservative uncertainty reported by a time
// source. Accuracy is encoded into TSTInfo; an unhealthy source must return an
// error so the service can fail closed with timeNotAvailable.
type Moment struct {
	Time     time.Time
	Accuracy time.Duration
}

type TimeSource interface {
	Now(context.Context) (Moment, error)
}

type SystemTimeSource struct {
	maxUncertainty   time.Duration
	requireKernelNTP bool
}

func NewSystemTimeSource(maxUncertainty time.Duration, requireKernelNTP bool) *SystemTimeSource {
	return &SystemTimeSource{maxUncertainty: maxUncertainty, requireKernelNTP: requireKernelNTP}
}

func (s *SystemTimeSource) Now(ctx context.Context) (Moment, error) {
	select {
	case <-ctx.Done():
		return Moment{}, ctx.Err()
	default:
	}
	if s.maxUncertainty <= 0 {
		return Moment{}, errors.New("maximum clock uncertainty must be positive")
	}
	uncertainty, synchronized, err := kernelClockHealth()
	if err != nil {
		if s.requireKernelNTP {
			return Moment{}, fmt.Errorf("read kernel clock synchronization: %w", err)
		}
		uncertainty = s.maxUncertainty
	} else if !synchronized {
		if s.requireKernelNTP {
			return Moment{}, errors.New("kernel reports the system clock as unsynchronized")
		}
		uncertainty = s.maxUncertainty
	}
	if uncertainty <= 0 {
		uncertainty = time.Millisecond
	}
	if uncertainty > s.maxUncertainty {
		return Moment{}, fmt.Errorf("clock uncertainty %s exceeds maximum %s", uncertainty, s.maxUncertainty)
	}
	return Moment{Time: time.Now().UTC().Truncate(time.Microsecond), Accuracy: uncertainty}, nil
}
