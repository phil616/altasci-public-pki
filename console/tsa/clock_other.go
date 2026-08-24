//go:build !linux

package tsa

import (
	"errors"
	"time"
)

func kernelClockHealth() (time.Duration, bool, error) {
	return 0, false, errors.New("kernel clock synchronization checks are only supported on Linux")
}
