package broker

import (
	"errors"
	"time"
)

// Current update timing does not change the stored attempt.
func (b *Broker) projectNextAllowedAt(view *releaseView, jobs ...*Job) error {
	related := false
	for _, job := range jobs {
		job.NextAllowedAt = nil
		related = related || job.UpdateID != "" || job.WaitReason != ""
	}
	if !related {
		return nil
	}
	status, err := b.updateStateLocked(view)
	if err != nil {
		// A refused optional control write leaves the timing unknown, which the job shows as null.
		var denied *Error
		if errors.As(err, &denied) && (denied.Code == "UPDATE_CLOCK_UNCERTAIN" || denied.Code == "QUOTA_EXCEEDED") {
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
