package freshclamadapter

type state struct {
	Initialized, Invalid, Blocked, Final bool
	DatSaveFailures, DatSaveAttempts     uint32
	RequestCount, ResponseCount          uint32
	HTTPStatus                           int32
	RetryAfter, MaxRetryAfter            int64
	ResponseUTC, WaitSeconds             int64
	UUID, LastRay, RetryRaw, DateRaw     string
}

type library interface {
	load(string) error
	bind(string) error
	restore(Snapshot) error
	initialize(string, string) error
	current() (state, error)
	update(string, bool) (int, error)
	verify(string) bool
	finish()
	cleanup()
	close()
}
