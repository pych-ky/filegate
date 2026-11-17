package broker

import (
	"context"
	"database/sql"
	"errors"
)

// 現在の許可だけを投影し、保存した検査試行の判定は変更しない。
// 表示は任意なので、制御の書き込みは管理DBの開始時の予算の中だけで行い、超えたら QUOTA_EXCEEDED を理由にする。
// v は一覧・詳細の1要求だけのメタデータで、実際の取り出しの認可には渡さない。
func (b *Broker) projectReleaseEligibility(ctx context.Context, job *Job, v *releaseView) error {
	b.projectScanProgress(job)
	job.Release = ReleaseEligibility{}
	_, err := b.releaseAuthorization(ctx, *job, func(tx *sql.Tx) error { return b.databaseBudget(tx) }, v)
	if err == nil {
		job.Release.Eligible = true
		return nil
	}
	var denied *Error
	if errors.As(err, &denied) {
		switch denied.Code {
		case "INCOMPLETE_REQUIRED_CHECKS", "REVALIDATION_REQUIRED", "UPDATE_CLOCK_UNCERTAIN", "INPUT_MISSING", "QUOTA_EXCEEDED":
			job.Release.ReasonCodes = []string{denied.Code}
			return nil
		}
	}
	return err
}
