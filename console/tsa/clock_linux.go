//go:build linux

package tsa

import (
	"time"

	"golang.org/x/sys/unix"
)

func kernelClockHealth() (time.Duration, bool, error) {
	var state unix.Timex
	clockState, err := unix.Adjtimex(&state)
	if err != nil {
		return 0, false, err
	}
	badStatus := int32(unix.STA_UNSYNC | unix.STA_CLOCKERR)
	synchronized := clockState != unix.TIME_ERROR && state.Status&badStatus == 0
	return time.Duration(state.Maxerror) * time.Microsecond, synchronized, nil
}
