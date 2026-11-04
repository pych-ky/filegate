package broker

import (
	"context"
	"errors"
	"time"
)

func (b *Broker) pruneAllowedLocked(scheduled bool) error {
	if b.closed {
		return failure("SERVICE_STOPPING", 503)
	}
	if len(b.active) > 0 || b.scanActive != nil || b.releaseActive != nil || (b.updates != nil && b.updates.active != nil) || b.recoveryBlocked {
		return failure("RESOURCE_BUSY", 429)
	}
	if scheduled {
		return b.pressureGateLocked()
	}
	return nil
}

func (b *Broker) retentionLoop() {
	defer close(b.retentionDone)
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-b.scanStop:
			return
		case <-timer.C:
		}
		_, err := b.prune(context.Background(), true)
		delay := time.Hour
		if err != nil {
			b.mu.Lock()
			if b.closed {
				b.mu.Unlock()
				return
			}
			var reason *Error
			if errors.As(err, &reason) && (reason.Code == "RESOURCE_BUSY" || reason.Code == "HOST_RESOURCE_PRESSURE" || reason.Code == "RESOURCE_MONITOR_FAILED") {
				delay = time.Minute
			} else {
				b.recoveryBlocked = true
			}
			b.mu.Unlock()
		}
		timer.Reset(delay)
	}
}
