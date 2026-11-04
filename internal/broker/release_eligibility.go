package broker

import (
	"context"
	"errors"
)

// 現在の許可だけを投影し、保存した検査試行の判定は変更しない。
func (b *Broker) projectReleaseEligibility(ctx context.Context, job *Job) error {
	b.projectScanProgress(job)
	job.Release = ReleaseEligibility{}
	_, err := b.currentReleaseAuthorization(ctx, *job)
	if err == nil {
		job.Release.Eligible = true
		return nil
	}
	var denied *Error
	if errors.As(err, &denied) {
		switch denied.Code {
		case "INCOMPLETE_REQUIRED_CHECKS", "REVALIDATION_REQUIRED", "UPDATE_CLOCK_UNCERTAIN", "INPUT_MISSING":
			job.Release.ReasonCodes = []string{denied.Code}
			return nil
		}
	}
	return err
}
