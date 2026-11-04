package verification

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Object = map[string]any

type Options struct {
	Root, Out, Binary, Driver, Proof, Runner, Workspace, DefinitionManifest, BinaryProof, Inputs string
	Mode, Suite                                                                                  string
	Cases                                                                                        []string
	Paths                                                                                        map[string]string
	PrepareOnly, IntakeOnly                                                                      bool
}

type Failure struct{ Name string }

func (e Failure) Error() string { return e.Name }

var suites = map[string]func(*Harness){}

func Register(name string, run func(*Harness)) {
	if suites[name] != nil {
		panic("DUPLICATE_SUITE")
	}
	suites[name] = run
}

type Harness struct {
	Options
	Data, InputDirectory, Socket string
	Record                       Object
	Checks                       []Object
	Responses, Logs              [][]byte
	Commands                     []Object
	Process                      *exec.Cmd
	processDone                  chan error
	stdout, stderr               bytes.Buffer
	Connections                  []net.Conn
	Temporary                    string
	StartTimeout, StopTimeout    time.Duration
}

func Decode(body []byte) Object {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var value Object
	if d.Decode(&value) != nil || value == nil || d.Decode(new(any)) != io.EOF {
		panic(Failure{"JSON_RESPONSE_INVALID"})
	}
	return value
}
func Encoded(value any) []byte { body, err := json.Marshal(value); Must(err); return body }
func Get(value any, keys ...string) any {
	for _, key := range keys {
		m, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = m[key]
	}
	return value
}
func Str(value any, keys ...string) string { text, _ := Get(value, keys...).(string); return text }
func Bool(value any, keys ...string) bool  { return Get(value, keys...) == true }
func Int(value any, keys ...string) int64 {
	switch n := Get(value, keys...).(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	case uint32:
		return int64(n)
	case uint:
		return int64(n)
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return i
		}
	case float64:
		return int64(n)
	}
	return -1
}
func Map(value any, keys ...string) Object { m, _ := Get(value, keys...).(map[string]any); return m }
func List(value any, keys ...string) []any { values, _ := Get(value, keys...).([]any); return values }
func Equal(a, b any) bool                  { return bytes.Equal(Encoded(a), Encoded(b)) }
func Contains(values any, expected any) bool {
	v, _ := values.([]any)
	for _, value := range v {
		if Equal(value, expected) {
			return true
		}
	}
	return false
}
func Must(err error) {
	if err != nil {
		panic(err)
	}
}
func Digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func FileDigest(path string) string {
	f, err := os.Open(path)
	Must(err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	Must(err)
	return hex.EncodeToString(h.Sum(nil))
}
func Read(path string) []byte     { body, err := os.ReadFile(path); Must(err); return body }
func ReadJSON(path string) Object { return Decode(Read(path)) }
func Write(path string, body []byte) {
	Must(os.MkdirAll(filepath.Dir(path), 0700))
	Must(os.WriteFile(path, body, 0600))
}
func WriteJSON(path string, value any) {
	body, err := json.MarshalIndent(value, "", "  ")
	Must(err)
	Write(path, append(body, '\n'))
}
func ErrorCode(value Object) string {
	if text, ok := value["error"].(string); ok {
		return text
	}
	return Str(value, "error", "code")
}
func Exists(path string) bool { _, err := os.Lstat(path); return !os.IsNotExist(err) }

func (h *Harness) Check(name string, passed bool, details ...Object) {
	row := Object{"name": name, "passed": passed}
	for _, detail := range details {
		for k, v := range detail {
			row[k] = v
		}
	}
	h.Checks = append(h.Checks, row)
	if !passed {
		panic(Failure{name})
	}
}
func (h *Harness) Connect() net.Conn {
	c, err := net.DialTimeout("unix", h.Socket, 3*time.Second)
	Must(err)
	Must(c.SetDeadline(time.Now().Add(3 * time.Second)))
	return c
}
func (h *Harness) Request(method, path string, value any, headers map[string]string, body []byte) (int, Object) {
	if value != nil {
		body = Encoded(value)
	}
	req, err := http.NewRequest(method, "http://filegate"+path, bytes.NewReader(body))
	Must(err)
	req.Close = true
	if value != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	c := h.Connect()
	defer c.Close()
	Must(req.Write(c))
	response, err := http.ReadResponse(bufio.NewReader(c), req)
	Must(err)
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	Must(err)
	h.Responses = append(h.Responses, raw)
	return response.StatusCode, Decode(raw)
}
func (h *Harness) UploadHeader(metadata Object, framing string, length int64) net.Conn {
	c := h.Connect()
	head := "POST /v1/uploads HTTP/1.1\r\nHost: filegate\r\nContent-Type: application/octet-stream\r\nFileGate-Metadata: " + base64.RawURLEncoding.EncodeToString(Encoded(metadata)) + "\r\n"
	if framing == "length" {
		head += "Content-Length: " + strconv.FormatInt(length, 10) + "\r\n"
	} else {
		head += "Transfer-Encoding: chunked\r\n"
	}
	_, err := io.WriteString(c, head+"\r\n")
	Must(err)
	return c
}
func (h *Harness) UnreadUpload(metadata Object, framing string) (int, Object, bool, time.Duration) {
	started := time.Now()
	c := h.UploadHeader(metadata, framing, 200000)
	defer c.Close()
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	Must(err)
	raw, err := io.ReadAll(response.Body)
	Must(err)
	Must(response.Body.Close())
	h.Responses = append(h.Responses, raw)
	var one [1]byte
	n, err := c.Read(one[:])
	return response.StatusCode, Decode(raw), n == 0 && err == io.EOF, time.Since(started)
}

type Command struct {
	Argv           []string `json:"argv"`
	ExitCode       int      `json:"exit_code"`
	Stdout, Stderr []byte
}

func Execute(directory string, args []string, input []byte, timeout time.Duration, files ...*os.File) Command {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir = directory
	command.Stdin = bytes.NewReader(input)
	command.ExtraFiles = files
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	code := 0
	if err != nil {
		if status, ok := err.(*exec.ExitError); ok {
			code = status.ExitCode()
		} else {
			panic(err)
		}
	}
	if ctx.Err() != nil {
		panic(Failure{"command_timeout"})
	}
	return Command{args, code, stdout.Bytes(), stderr.Bytes()}
}
func (h *Harness) command(arguments []string, input []byte, files ...*os.File) (int, Object) {
	args := append([]string{h.Binary, "--data-dir", h.Data}, arguments...)
	result := Execute(h.Root, args, input, 10*time.Second, files...)
	h.Responses = append(h.Responses, result.Stdout, result.Stderr)
	h.Commands = append(h.Commands, Object{"operation": arguments[0], "exit_code": result.ExitCode})
	return result.ExitCode, Decode(result.Stdout)
}
func (h *Harness) CLI(arguments ...string) (int, Object) { return h.command(arguments, nil) }
func (h *Harness) CLIInput(input []byte, arguments ...string) (int, Object) {
	return h.command(arguments, input)
}
func (h *Harness) Submit(kind, source string, metadata Object, input []byte) (int, Object) {
	copy := Object{"source": source}
	for k, v := range metadata {
		copy[k] = v
	}
	file, err := os.CreateTemp(h.Out, "metadata-*.json")
	Must(err)
	defer os.Remove(file.Name())
	defer file.Close()
	_, err = file.Write(Encoded(copy))
	Must(err)
	_, err = file.Seek(0, 0)
	Must(err)
	code, value := h.command([]string{"submit", kind, "--metadata-fd", "3"}, input, file)
	if len(h.Commands) > 0 {
		h.Commands[len(h.Commands)-1]["source_kind"] = kind
		h.Commands[len(h.Commands)-1]["metadata_transport"] = "fd"
	}
	return code, value
}
func (h *Harness) MCP(messages []Object) (int, map[int64]Object) {
	var input []byte
	for _, message := range messages {
		input = append(append(input, Encoded(message)...), '\n')
	}
	result := Execute(h.Root, []string{h.Binary, "--data-dir", h.Data, "mcp"}, input, 10*time.Second)
	h.Responses = append(h.Responses, result.Stdout, result.Stderr)
	replies := map[int64]Object{}
	for _, line := range bytes.Split(bytes.TrimSpace(result.Stdout), []byte{'\n'}) {
		if len(line) > 0 {
			reply := Decode(line)
			replies[Int(reply, "id")] = reply
		}
	}
	return result.ExitCode, replies
}
func MCPInit() []Object {
	return []Object{{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": Object{"protocolVersion": "2025-06-18", "capabilities": Object{}, "clientInfo": Object{"name": "filegate-e2e", "version": "1"}}}, {"jsonrpc": "2.0", "method": "notifications/initialized"}}
}
func MCPCall(id int, name string, args Object) Object {
	return Object{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": Object{"name": name, "arguments": args}}
}
func MCPValue(reply Object) Object {
	contents := List(reply, "result", "content")
	if len(contents) == 0 {
		panic(Failure{"MCP_CONTENT_MISSING"})
	}
	return Decode([]byte(Str(contents[0], "text")))
}

func (h *Harness) Start(extra ...string) Object {
	if h.Process != nil {
		panic(Failure{"service_already_started"})
	}
	h.stdout.Reset()
	h.stderr.Reset()
	args := []string{"--data-dir", h.Data, "serve", "--input-root", "fixture=" + h.InputDirectory, "--input-root", "alias=" + h.InputDirectory}
	args = append(args, extra...)
	h.Process = exec.Command(h.Binary, args...)
	h.Process.Stdout = &h.stdout
	h.Process.Stderr = &h.stderr
	Must(h.Process.Start())
	h.processDone = make(chan error, 1)
	process := h.Process
	done := h.processDone
	go func() { done <- process.Wait() }()
	timeout := 8 * time.Second
	for _, argument := range extra {
		if argument == "--vm-runner" {
			timeout = 30 * time.Second
		}
	}
	if h.StartTimeout > 0 {
		timeout = h.StartTimeout
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			h.Logs = append(h.Logs, append([]byte{}, h.stdout.Bytes()...), append([]byte{}, h.stderr.Bytes()...))
			h.Process = nil
			panic(fmt.Errorf("service_start:%v", err))
		default:
		}
		var health Object
		func() {
			defer func() { _ = recover() }()
			status, value := h.Request("GET", "/v1/health", nil, nil, nil)
			if status == 200 {
				health = value
			}
		}()
		if health != nil {
			return health
		}
		time.Sleep(30 * time.Millisecond)
	}
	panic(Failure{"service_start_timeout"})
}
func (h *Harness) Stop(crash bool) {
	if h.Process == nil {
		return
	}
	process := h.Process
	timeout := 8 * time.Second
	if h.Paths["vm-runner"] != "" {
		timeout = 30 * time.Second
	}
	if h.StopTimeout > 0 {
		timeout = h.StopTimeout
	}
	select {
	case err := <-h.processDone:
		h.Process = nil
		h.Logs = append(h.Logs, append([]byte{}, h.stdout.Bytes()...), append([]byte{}, h.stderr.Bytes()...))
		if !crash {
			h.Check("service_stop", err == nil)
		}
		return
	default:
	}
	if crash {
		Must(process.Process.Kill())
	} else {
		Must(process.Process.Signal(syscall.SIGTERM))
	}
	select {
	case err := <-h.processDone:
		h.Process = nil
		h.Logs = append(h.Logs, append([]byte{}, h.stdout.Bytes()...), append([]byte{}, h.stderr.Bytes()...))
		if !crash {
			h.Check("service_stop", err == nil)
		}
	case <-time.After(timeout):
		_ = process.Process.Kill()
		<-h.processDone
		h.Process = nil
		h.Logs = append(h.Logs, append([]byte{}, h.stdout.Bytes()...), append([]byte{}, h.stderr.Bytes()...))
		panic(Failure{"service_stop_timeout"})
	}
}

func (h *Harness) ServiceAlive() bool {
	if h.Process == nil {
		return false
	}
	select {
	case err := <-h.processDone:
		h.processDone <- err
		return false
	default:
		return true
	}
}
func (h *Harness) WaitJob(id string, terminal bool) Object {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, job := h.Request("GET", "/v1/jobs/"+id, nil, nil, nil)
		phase := Str(job, "phase")
		done := phase == "FINISHED" || phase == "FAILED" || phase == "CANCELLED"
		if status == 200 && done == terminal {
			return job
		}
		time.Sleep(20 * time.Millisecond)
	}
	panic(Failure{"job_transition_timeout"})
}
func (h *Harness) BeginPartial(key string) (Object, net.Conn, string) {
	_, before := h.Request("GET", "/v1/jobs", nil, nil, nil)
	previous := map[string]bool{}
	for _, job := range List(before, "jobs") {
		previous[Str(job, "job_id")] = true
	}
	metadata := Object{"source_kind": "upload", "idempotency_key": key, "display_name": "synthetic.txt"}
	c := h.UploadHeader(metadata, "length", 1048576)
	h.Connections = append(h.Connections, c)
	_, err := c.Write([]byte("A"))
	Must(err)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, current := h.Request("GET", "/v1/jobs", nil, nil, nil)
		pending := []string{}
		for _, job := range List(current, "jobs") {
			if !previous[Str(job, "job_id")] && Str(job, "phase") == "ACQUIRING" {
				pending = append(pending, Str(job, "job_id"))
			}
		}
		if len(pending) == 1 {
			return metadata, c, pending[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	panic(Failure{"acquisition_not_observed"})
}
func (h *Harness) Query(query string, args ...any) [][]any {
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(h.Data, "state.sqlite")+"?mode=ro")
	Must(err)
	defer db.Close()
	rows, err := db.Query(query, args...)
	Must(err)
	defer rows.Close()
	columns, err := rows.Columns()
	Must(err)
	result := [][]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		Must(rows.Scan(pointers...))
		result = append(result, values)
	}
	Must(rows.Err())
	return result
}
