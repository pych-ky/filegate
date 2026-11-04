//go:build !linux || !arm64 || !cgo

package freshclamadapter

func newLibrary() (library, error) { return nil, invalid }
func flushLibraryOutput()          {}
