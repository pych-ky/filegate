package broker

import (
	"errors"
	"time"
)

// Current update timing does not change the stored attempt.
func (b *Broker) projectNextAllowedAt(jobs ...*Job) error {
	related := false
	for _, job := range jobs {
		job.NextAllowedAt = nil
		related = related || job.UpdateID != "" || job.WaitReason != ""
	}
	if !related {
		return nil
	}
	status, err := b.updateStateLocked()
	if err != nil {
		var denied *Error
		if errors.As(err, &denied) && denied.Code == "UPDATE_CLOCK_UNCERTAIN" {
			return nil
		}
		return err
	}
	if status.NextAllowedUTC != nil {
		value := time.Unix(*status.NextAllowedUTC, 0).UTC().Format(time.RFC3339)
		for _, job := range jobs {
			if job.UpdateID != "" || job.WaitReason != "" {
				job.NextAllowedAt = &value
			}
		}
	}
	return nil
}
