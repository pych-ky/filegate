package broker

import (
	"errors"
	"filegate.local/filegate/internal/pressure"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type hostPressure struct {
	monitor     *pressure.Monitor
	blocked     bool
	marker      bool
	failed      bool
	normalSince uint64
	lastClock   uint64
	reason      string
	stop        chan struct{}
	done        chan struct{}
}

func (b *Broker) pressureMarker(blocked bool) error {
	path := filepath.Join(b.config.DataDir, "host-pressure.blocked")
	file, err := openPrivate(path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) && blocked {
		file, err = openPrivate(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	defer file.Close()
	var actual, current unix.Stat_t
	if unix.Fstat(int(file.Fd()), &actual) != nil || unix.Lstat(path, &current) != nil ||
		actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Mode&07777 != 0600 || actual.Uid != uint32(os.Geteuid()) || actual.Size != 0 || actual.Nlink != 1 || actual.Dev != current.Dev || actual.Ino != current.Ino {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	if blocked {
		err = syncFile(file)
	} else {
		err = os.Remove(path)
	}
	if err == nil {
		err = syncDirectory(b.config.DataDir)
	}
	if err != nil {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	return nil
}

func (b *Broker) configurePressure() error {
	monitor, err := pressure.Open()
	if err != nil {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	p := &hostPressure{monitor: monitor, stop: make(chan struct{}), done: make(chan struct{})}
	b.pressure = p
	if _, err = os.Lstat(filepath.Join(b.config.DataDir, "host-pressure.blocked")); err == nil {
		if err = b.pressureMarker(true); err != nil {
			monitor.Close()
			return err
		}
		p.blocked, p.marker, p.reason = true, true, "HOST_RESOURCE_PRESSURE"
	} else if !errors.Is(err, os.ErrNotExist) {
		monitor.Close()
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	sample, err := monitor.Read()
	if err != nil {
		_ = b.pressureMarker(true)
		monitor.Close()
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	b.observePressureLocked(sample, nil, false)
	if p.failed {
		monitor.Close()
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	return nil
}

func (b *Broker) observePressureLocked(sample pressure.Sample, measurement error, allowRecovery bool) {
	p := b.pressure
	if p == nil || b.closed {
		return
	}
	if p.failed || sample.ContinuousNS < p.lastClock {
		measurement = pressure.Unavailable
	}
	if measurement == nil {
		p.lastClock = sample.ContinuousNS
	}
	if measurement != nil || sample.Level != pressure.Normal || sample.Pending&(pressure.Warning|pressure.Critical) != 0 {
		p.blocked, p.normalSince, p.reason = true, 0, "HOST_RESOURCE_PRESSURE"
		if measurement != nil {
			p.reason = "RESOURCE_MONITOR_FAILED"
		}
		cause := failure(p.reason, 503)
		for _, run := range b.active {
			run.stopCause(cause)
		}
		if b.releaseActive != nil {
			b.releaseActive.stopCause(cause)
		}
		if measurement != nil && b.scanActive != nil {
			b.scanActive.stopFor("RESOURCE_MONITOR_FAILED")
		}
		if !p.marker {
			if err := b.pressureMarker(true); err != nil {
				p.failed, p.reason, b.recoveryBlocked = true, "RESOURCE_MONITOR_FAILED", true
			} else {
				p.marker = true
			}
		}
	}
	if measurement != nil || sample.Level != pressure.Normal || !p.blocked {
		return
	}
	if p.normalSince == 0 {
		p.normalSince = sample.ContinuousNS
	}
	if !allowRecovery || sample.ContinuousNS-p.normalSince < uint64(30*time.Second) || b.recoveryBlocked || len(b.active) != 0 || b.scanActive != nil || b.releaseActive != nil {
		return
	}
	if b.inputStorageCapacityLocked() != nil {
		return
	}
	if err := b.pressureMarker(false); err != nil {
		// A failed clear never admits work; restore the durable stop marker when possible.
		_ = b.pressureMarker(true)
		p.failed, p.reason, b.recoveryBlocked = true, "RESOURCE_MONITOR_FAILED", true
		return
	}
	p.blocked, p.marker, p.reason = false, false, ""
}

func (b *Broker) pressureGateLocked() error {
	if b.closed {
		return failure("SERVICE_STOPPING", 503)
	}
	if b.pressure == nil {
		return failure("RESOURCE_MONITOR_FAILED", 503)
	}
	sample, err := b.pressure.monitor.Read()
	b.observePressureLocked(sample, err, false)
	if b.pressure.blocked {
		return failure(b.pressure.reason, 503)
	}
	return nil
}

func (b *Broker) pressureLoop() {
	p := b.pressure
	defer close(p.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	events := p.monitor.Events()
	for {
		failed := false
		select {
		case <-p.stop:
			return
		case _, open := <-events:
			if !open {
				events, failed = nil, true
			}
		case <-ticker.C:
		}
		b.mu.Lock()
		if !b.closed {
			p.failed = p.failed || failed
			before := p.blocked
			sample, err := p.monitor.Read()
			b.observePressureLocked(sample, err, true)
			if before && !p.blocked {
				b.startNextURLLocked()
				b.nextReleaseLocked()
				b.wakeScan()
			}
		}
		b.mu.Unlock()
	}
}

func (b *Broker) closePressure() {
	if b.pressure != nil {
		close(b.pressure.stop)
		<-b.pressure.done
		b.pressure.monitor.Close()
	}
}
