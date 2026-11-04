package pressure

import "errors"

const (
	Normal   uint32 = 1
	Warning  uint32 = 2
	Critical uint32 = 4
)

var Unavailable = errors.New("RESOURCE_MONITOR_FAILED")

type Sample struct {
	Level        uint32
	Pending      uint32
	ContinuousNS uint64
}
