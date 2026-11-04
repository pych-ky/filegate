package fixtures

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var invalid = errors.New("FIXTURE_VALIDATION_FAILED")

func digest(body []byte) string {
	value := sha256.Sum256(body)
	return hex.EncodeToString(value[:])
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func decode(body []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return invalid
	}
	return nil
}

func write(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(body, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func guest() bool {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || os.Geteuid() != 65534 || os.Getegid() != 65534 {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		return false
	}
	body, err := os.ReadFile("/proc/self/status")
	return err == nil && strings.Contains(string(body), "NoNewPrivs:\t1\n") && strings.Contains(string(body), "CapEff:\t0000000000000000\n")
}

type outputBudget struct {
	mu     sync.Mutex
	used   int
	limit  int
	failed bool
	cancel context.CancelFunc
}

type boundedOutput struct {
	budget *outputBudget
	buffer bytes.Buffer
}

func (w *boundedOutput) Write(body []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	if len(body) > w.budget.limit-w.budget.used {
		w.budget.failed = true
		w.budget.cancel()
		return 0, invalid
	}
	w.budget.used += len(body)
	return w.buffer.Write(body)
}

func command(arguments []string, input []byte, limit int, environment []string) ([]byte, []byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	budget := &outputBudget{limit: limit, cancel: cancel}
	stdout, stderr := &boundedOutput{budget: budget}, &boundedOutput{budget: budget}
	cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.Env, cmd.WaitDelay = bytes.NewReader(input), stdout, stderr, environment, time.Second
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil || budget.failed {
		return nil, nil, code, invalid
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		err = nil
	}
	return stdout.buffer.Bytes(), stderr.buffer.Bytes(), code, err
}
