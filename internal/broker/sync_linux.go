package broker

import "os"

func syncFile(f *os.File) error { return f.Sync() }
