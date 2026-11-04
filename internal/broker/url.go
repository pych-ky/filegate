package broker

import "context"

type urlIntake struct {
	request  Request
	job      Job
	objectID string
}

func (b *Broker) startNextURLLocked() {
	if b.closed || b.recoveryBlocked || len(b.active) != 0 || len(b.urlQueue) == 0 {
		return
	}
	if b.pressureGateLocked() != nil {
		return
	}
	next := b.urlQueue[0]
	b.urlQueue = b.urlQueue[1:]
	next.job.Phase = "ACQUIRING"
	next.job.IntakeStatus = "ACQUIRING"
	if _, err := b.db.Exec("UPDATE jobs SET data=? WHERE id=?", encode(next.job), next.job.JobID); err != nil {
		b.recoveryBlocked = true
		return
	}
	ctx, stopCause := context.WithCancelCause(context.Background())
	run := &ingestRun{cancel: func() { stopCause(context.Canceled) }, stopCause: stopCause, done: make(chan struct{})}
	b.active[next.job.JobID] = run
	go func() { b.acquireInput(ctx, next.request, nil, next.job, next.objectID, run) }()
}

func (b *Broker) pendingInputs(q queryer) (int64, error) {
	var count int64
	if q.QueryRowContext(context.Background(), "SELECT count(*) FROM reservations").Scan(&count) != nil {
		return 0, storageError()
	}
	pending := count * MaxInputBytes
	for id, run := range b.active {
		var owned int
		if q.QueryRowContext(context.Background(), "SELECT count(*) FROM reservations WHERE job_id=?", id).Scan(&owned) != nil {
			return 0, storageError()
		}
		if owned != 0 {
			pending -= run.written
		}
	}
	return pending, nil
}
