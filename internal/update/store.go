package update

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sync"
)

const schema = `
CREATE TABLE IF NOT EXISTS update_control(scope TEXT PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS update_attempts(id TEXT PRIMARY KEY, data BLOB NOT NULL, reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0));
CREATE TABLE IF NOT EXISTS update_waiters(attempt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, update_id TEXT NOT NULL REFERENCES update_attempts(id));
CREATE TABLE IF NOT EXISTS update_runtime(update_id TEXT PRIMARY KEY REFERENCES update_attempts(id), directory TEXT NOT NULL UNIQUE, manifest_sha256 TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS update_adoptions(update_id TEXT PRIMARY KEY REFERENCES update_attempts(id), data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS update_definition_caches(update_id TEXT PRIMARY KEY REFERENCES update_attempts(id) ON DELETE CASCADE, data BLOB NOT NULL, data_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS update_retention(update_id TEXT PRIMARY KEY REFERENCES update_attempts(id) ON DELETE CASCADE, resolved_at INTEGER NOT NULL, definition_removed INTEGER NOT NULL DEFAULT 0, runtime_removed INTEGER NOT NULL DEFAULT 0, pending BLOB, reason TEXT NOT NULL DEFAULT '');
`

type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	hostClock bool
}

func Open(db *sql.DB) (*Store, error) {
	for name, expected := range map[string]int{"synchronous": 2, "fullfsync": 1, "foreign_keys": 1} {
		var actual int
		if db.QueryRow("PRAGMA "+name).Scan(&actual) != nil || actual != expected {
			return nil, Error("STORE_UNAVAILABLE")
		}
	}
	var mode string
	if db.QueryRow("PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		return nil, Error("STORE_UNAVAILABLE")
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// OpenHostClock samples the host clock after acquiring the transaction for each operation.
func OpenHostClock(db *sql.DB) (*Store, error) {
	s, err := Open(db)
	if err == nil {
		s.hostClock = true
	}
	return s, err
}

func (s *Store) Initialize(binding Binding, now Clock) (Control, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !digestPattern.MatchString(binding.LibrarySHA256) {
		return Control{}, Invalid
	}
	uuid, err := newUUID()
	if err != nil {
		return Control{}, err
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Control{}, err
	}
	defer tx.Rollback()
	if s.hostClock {
		now, err = ReadClock()
		if err != nil {
			return Control{}, err
		}
	}
	if !now.Valid() {
		return Control{}, Invalid
	}
	c := Control{State: "READY", Binding: binding, Clock: now,
		Snapshot: Snapshot{SchemaVersion: 1, Engine: Engine, Adapter: Adapter, UUID: uuid}}
	data, _ := SnapshotBytes(c.Snapshot)
	c.SnapshotSHA256 = sha256Text(data)
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM update_control").Scan(&count); err != nil {
		return Control{}, err
	}
	if count != 0 {
		return Control{}, Error("UPDATE_ALREADY_INITIALIZED")
	}
	if err = tx.QueryRow("SELECT count(*) FROM update_attempts").Scan(&count); err != nil {
		return Control{}, err
	}
	if count != 0 {
		return Control{}, Unknown
	}
	if _, err = tx.Exec("INSERT INTO update_control(scope,data) VALUES(?,?)", Scope, encoded(c)); err != nil {
		return Control{}, err
	}
	return c, tx.Commit()
}

func loadControl(tx *sql.Tx) (Control, error) {
	var c Control
	var data []byte
	if err := tx.QueryRow("SELECT data FROM update_control WHERE scope=?", Scope).Scan(&data); err != nil {
		return c, err
	}
	if decodeStored(data, &c) != nil || c.Generation < 0 || !c.Clock.Valid() || c.NextAllowedUTC < 0 || c.NextAllowedUTC > MaxUTC ||
		c.RemainingSeconds < 0 || c.RemainingSeconds > MaxUTC || c.ContinuousRemainingSeconds < 0 || c.ContinuousRemainingSeconds > c.RemainingSeconds ||
		c.WaitFractionNS >= 1e9 || !digestPattern.MatchString(c.Binding.LibrarySHA256) ||
		c.ActiveUpdateID != "" && !identifier.MatchString(c.ActiveUpdateID) {
		return c, Invalid
	}
	if c.State != "READY" && c.State != "COOLDOWN" && c.State != "IN_FLIGHT" && c.State != "UNKNOWN" {
		return c, Invalid
	}
	if c.RemainingSeconds != max(c.ContinuousRemainingSeconds, c.NextAllowedUTC-c.Clock.UTC) ||
		c.ContinuousRemainingSeconds == 0 && c.WaitFractionNS != 0 {
		return c, Invalid
	}
	data, err := SnapshotBytes(c.Snapshot)
	if err != nil || sha256Text(data) != c.SnapshotSHA256 {
		return c, Invalid
	}
	return c, nil
}

func decodeStored(data []byte, target any) error {
	before, err := decode(data, 16<<10)
	if err != nil || json.Unmarshal(data, target) != nil {
		return Invalid
	}
	after, err := decode(encoded(target), 16<<10)
	if err != nil || !reflect.DeepEqual(before, after) {
		return Invalid
	}
	return nil
}

func loadAttempt(tx *sql.Tx, id string) (Attempt, error) {
	var a Attempt
	var data []byte
	var reserved int64
	if err := tx.QueryRow("SELECT data,reserved_bytes FROM update_attempts WHERE id=?", id).Scan(&data, &reserved); err != nil {
		return a, err
	}
	if decodeStored(data, &a) != nil || a.ID != id || !identifier.MatchString(id) || !a.Started.Valid() ||
		a.BaseGeneration < 0 || a.BaseGeneration > math.MaxInt64-2 || a.DeadlineContinuousNS < a.Started.ContinuousNS ||
		a.DeadlineContinuousNS-a.Started.ContinuousNS != uint64(DeadlineSeconds)*1e9 || a.ReservedBytes != reserved || a.ReservedBytes < 0 || a.ReservedBytes > WorkspaceReservation {
		return a, Invalid
	}
	if a.FinalReceived != nil && (!a.FinalReceived.Valid() || !a.ControlCommitted) {
		return a, Invalid
	}
	return a, nil
}

func saveAttempt(tx *sql.Tx, a Attempt) error {
	_, err := tx.Exec("INSERT INTO update_attempts(id,data,reserved_bytes) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,reserved_bytes=excluded.reserved_bytes", a.ID, encoded(a), a.ReservedBytes)
	return err
}

func advance(c *Control, now Clock) error {
	if !now.Valid() || now.Boot == c.Clock.Boot && now.ContinuousNS < c.Clock.ContinuousNS {
		c.State, c.Reason = "UNKNOWN", string(ClockUncertain)
		return ClockUncertain
	}
	continuousRemaining := c.RemainingSeconds
	fraction := uint64(0)
	if now.Boot == c.Clock.Boot {
		elapsed := now.ContinuousNS - c.Clock.ContinuousNS
		fraction = c.WaitFractionNS + elapsed%1e9
		continuousRemaining = max(int64(0), c.ContinuousRemainingSeconds-int64(elapsed/1e9)-int64(fraction/1e9))
		fraction %= 1e9
	}
	if continuousRemaining == 0 {
		fraction = 0
	}
	remaining := max(continuousRemaining, c.NextAllowedUTC-now.UTC)
	if remaining > MaxUTC-now.UTC {
		c.State, c.Reason = "UNKNOWN", string(ClockUncertain)
		return ClockUncertain
	}
	if now.Boot != c.Clock.Boot && remaining != 0 {
		c.NextAllowedUTC = max(c.NextAllowedUTC, now.UTC+remaining)
	}
	c.Clock, c.RemainingSeconds = now, remaining
	c.ContinuousRemainingSeconds, c.WaitFractionNS = continuousRemaining, fraction
	if c.State == "COOLDOWN" && remaining == 0 && c.ActiveUpdateID == "" {
		c.State, c.Reason = "READY", ""
	}
	return nil
}

func (s *Store) apply(now Clock, operation func(*sql.Tx, *Control, Clock) error) (Control, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Control{}, err
	}
	defer tx.Rollback()
	c, err := loadControl(tx)
	if err != nil {
		return c, err
	}
	if s.hostClock {
		now, err = ReadClock()
		if err != nil {
			return c, err
		}
	}
	operationErr := advance(&c, now)
	if operationErr == nil && operation != nil {
		operationErr = operation(tx, &c, now)
	}
	var domain Error
	if operationErr != nil && !errors.As(operationErr, &domain) {
		return c, operationErr
	}
	if _, err = tx.Exec("UPDATE update_control SET data=? WHERE scope=?", encoded(c), Scope); err != nil {
		return c, err
	}
	if err = tx.Commit(); err != nil {
		return c, err
	}
	return c, operationErr
}

func (s *Store) Read(now Clock) (Control, error) { return s.apply(now, nil) }

func (s *Store) Begin(id string, now Clock) (Control, Attempt, error) {
	return s.begin(id, now, nil)
}

func (s *Store) begin(id string, now Clock, reserve func(*sql.Tx, Control) error) (Control, Attempt, error) {
	var result Attempt
	c, err := s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		if !identifier.MatchString(id) {
			return Invalid
		}
		if c.State == "UNKNOWN" {
			return Unknown
		}
		if c.ActiveUpdateID != "" {
			var err error
			result, err = loadAttempt(tx, c.ActiveUpdateID)
			if err != nil {
				return err
			}
			if c.State != "IN_FLIGHT" {
				return Busy
			}
			return nil
		}
		if c.State == "IN_FLIGHT" {
			c.State, c.Reason = "UNKNOWN", string(Unknown)
			return Unknown
		}
		if c.RemainingSeconds != 0 || now.UTC < c.NextAllowedUTC {
			return Cooldown
		}
		if c.Generation >= math.MaxInt64-1 || now.ContinuousNS > math.MaxUint64-uint64(DeadlineSeconds)*1e9 {
			return ClockUncertain
		}
		var duplicate int
		if err := tx.QueryRow("SELECT count(*) FROM update_attempts WHERE id=?", id).Scan(&duplicate); err != nil {
			return err
		}
		if duplicate != 0 {
			return StaleReport
		}
		result = Attempt{ID: id, BaseGeneration: c.Generation, State: "PREPARING", Started: now,
			DeadlineContinuousNS: now.ContinuousNS + uint64(DeadlineSeconds)*1e9, ReservedBytes: WorkspaceReservation}
		c.Generation++
		c.LastUpdateID = id
		c.State, c.ActiveUpdateID, c.Reason = "IN_FLIGHT", id, ""
		if err := saveAttempt(tx, result); err != nil {
			return err
		}
		if reserve != nil {
			return reserve(tx, *c)
		}
		return nil
	})
	return c, result, err
}

func deadline(a Attempt, now Clock) error {
	if now.Boot != a.Started.Boot || now.ContinuousNS < a.Started.ContinuousNS {
		return ClockUncertain
	}
	if now.ContinuousNS >= a.DeadlineContinuousNS {
		return Timeout
	}
	return nil
}

func (s *Store) Restore(id string, now Clock) (RestoreRequest, error) {
	var request RestoreRequest
	_, err := s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		if c.ActiveUpdateID != id || c.State != "IN_FLIGHT" {
			return Unknown
		}
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if a.Reason != "" {
			return Error(a.Reason)
		}
		if err = deadline(a, now); err != nil {
			return err
		}
		request = RestoreRequest{1, id, a.BaseGeneration, c.Snapshot}
		return nil
	})
	return request, err
}

func (s *Store) Final(id string, raw []byte, now Clock) (Control, error) {
	return s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if c.Generation != a.BaseGeneration+1 {
			return StaleReport
		}
		if a.ControlCommitted {
			if a.FinalSHA256 == sha256Text(raw) {
				return nil
			}
			return StaleReport
		}
		if c.ActiveUpdateID != id && !(c.ActiveUpdateID == "" && c.State == "UNKNOWN" && a.StopConfirmed) {
			return StaleReport
		}
		final, validationErr := ValidateFinal(raw, now, c.Snapshot, c.Binding)
		if validationErr == nil && (final.UpdateID != id || final.BaseGeneration != a.BaseGeneration) {
			return StaleReport
		}
		if validationErr != nil {
			c.State, c.Reason = "UNKNOWN", validationErr.Error()
			return validationErr
		}
		if now.Boot == a.Started.Boot && now.ContinuousNS < a.Started.ContinuousNS {
			c.State, c.Reason = "UNKNOWN", string(ClockUncertain)
			return ClockUncertain
		}
		var elapsed int64
		if now.Boot == a.Started.Boot {
			elapsed = int64((now.ContinuousNS - a.Started.ContinuousNS) / 1e9)
		}
		wait := max(final.WaitSeconds, c.RemainingSeconds, c.NextAllowedUTC-now.UTC,
			max(int64(0), a.Started.UTC+MinimumInterval-now.UTC, MinimumInterval-elapsed))
		if wait > MaxUTC-now.UTC {
			c.State, c.Reason = "UNKNOWN", string(ClockUncertain)
			return ClockUncertain
		}
		c.Snapshot, c.SnapshotSHA256 = final.Snapshot, sha256Text(final.SnapshotBytes)
		c.State, c.Reason, c.NextAllowedUTC, c.RemainingSeconds = "COOLDOWN", "", now.UTC+wait, wait
		c.ContinuousRemainingSeconds = wait
		c.WaitFractionNS = 0
		a.ControlCommitted, a.FinalSHA256, a.OriginConfirmed = true, final.SHA256, final.OriginVerified
		if !c.Binding.FixtureOnly {
			a.FinalReceived = &now
		}
		if a.Reason == "" {
			if err := deadline(a, now); err != nil {
				a.Reason = err.Error()
				if !a.StopConfirmed {
					a.State = "STOPPING"
				}
			}
		}
		return saveAttempt(tx, a)
	})
}

func (s *Store) Stop(id, reason string, now Clock) (Control, error) {
	return s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		if c.ActiveUpdateID != id {
			return StaleReport
		}
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if a.AdoptionApproved {
			return nil
		}
		switch reason {
		case "UPDATE_TIMEOUT", "INTERRUPTED", "CANCELLED", "RESOURCE_MONITOR_FAILED", "HOST_RESOURCE_PRESSURE", "WORKSPACE_IO_ERROR", "UPDATE_CLOCK_UNCERTAIN":
		default:
			return Invalid
		}
		if a.Reason == "" {
			a.Reason = reason
		}
		a.State = "STOPPING"
		if !a.ControlCommitted {
			c.State, c.Reason = "UNKNOWN", string(Unknown)
		}
		return saveAttempt(tx, a)
	})
}

func (s *Store) Recover(now Clock) (Control, error) {
	return s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		if c.ActiveUpdateID == "" {
			return nil
		}
		a, err := loadAttempt(tx, c.ActiveUpdateID)
		if err != nil {
			return err
		}
		if a.AdoptionApproved {
			return nil
		}
		if a.Reason == "" {
			a.Reason = "INTERRUPTED"
		}
		a.State = "STOPPING"
		if !a.ControlCommitted {
			c.State, c.Reason = "UNKNOWN", string(Unknown)
		}
		return saveAttempt(tx, a)
	})
}

// Stop and storage reclamation settle different reservations.
func (s *Store) Stopped(id string, cleaned bool, now Clock) (Control, error) {
	return s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if c.ActiveUpdateID != id && !a.StopConfirmed {
			return StaleReport
		}
		if a.StopConfirmed && a.CleanupConfirmed {
			return nil
		}
		a.StopConfirmed = true
		if cleaned {
			a.CleanupConfirmed, a.ReservedBytes = true, 0
		}
		if !a.CleanupConfirmed {
			a.State = "CLEANUP_PENDING"
		} else {
			a.State, a.FinishedUTC = "FINISHED", now.UTC
		}
		if c.ActiveUpdateID == id {
			c.ActiveUpdateID = ""
			if !a.ControlCommitted {
				c.State, c.Reason = "UNKNOWN", string(Unknown)
			}
		}
		return saveAttempt(tx, a)
	})
}

func (s *Store) Attempt(id string) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback()
	return loadAttempt(tx, id)
}

func (s *Store) CheckDeadline(id string, now Clock) error {
	_, err := s.apply(now, func(tx *sql.Tx, c *Control, now Clock) error {
		a, err := loadAttempt(tx, id)
		if err != nil {
			return err
		}
		if a.AdoptionApproved {
			return nil
		}
		if c.ActiveUpdateID != id && !a.StopConfirmed {
			return StaleReport
		}
		if a.Reason != "" {
			return Error(a.Reason)
		}
		if err = deadline(a, now); err != nil {
			a.Reason = err.Error()
			if !a.StopConfirmed {
				a.State = "STOPPING"
			}
			if !a.ControlCommitted {
				c.State, c.Reason = "UNKNOWN", string(Unknown)
			}
			if saveErr := saveAttempt(tx, a); saveErr != nil {
				return saveErr
			}
			return err
		}
		return nil
	})
	return err
}

func Fresh(c Control, now Clock) bool {
	d := c.Definition
	return d != nil && now.Valid() && d.Confirmed.Valid() && d.Confirmed.Boot == now.Boot && now.UTC >= d.Confirmed.UTC &&
		now.UTC-d.Confirmed.UTC <= FreshnessSeconds && now.ContinuousNS >= d.Confirmed.ContinuousNS &&
		now.ContinuousNS-d.Confirmed.ContinuousNS <= uint64(FreshnessSeconds)*1e9 && digestPattern.MatchString(d.ManifestSHA256)
}
