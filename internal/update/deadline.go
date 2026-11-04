package update

import (
	"context"
	"time"
)

// Termination is requested before waiting for the SQLite writer.
func (s *Store) Monitor(ctx context.Context, attempt Attempt, terminate func(string)) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now, err := ReadClock()
				if err == nil {
					err = deadline(attempt, now)
				}
				if err != nil {
					terminate(err.Error())
					_, stored := s.Stop(attempt.ID, err.Error(), now)
					if stored != nil {
						done <- stored
					} else {
						done <- err
					}
					return
				}
			}
		}
	}()
	return done
}
