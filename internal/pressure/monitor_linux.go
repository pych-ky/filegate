package pressure

type Monitor struct{}

func Open() (*Monitor, error)              { return nil, Unavailable }
func (m *Monitor) Read() (Sample, error)   { return Sample{}, Unavailable }
func (m *Monitor) Events() <-chan struct{} { return nil }
func (m *Monitor) Close()                  {}
