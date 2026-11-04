package verification

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type UIClient struct {
	H                  *Harness
	Origin             string
	bootstrap, session string
}

func (u *UIClient) Request(method, path string, body []byte, headers map[string]string, auth, origin, csrf bool) (int, http.Header, []byte) {
	target, err := url.Parse(u.Origin)
	Must(err)
	c, err := net.DialTimeout("tcp", target.Host, 5*time.Second)
	Must(err)
	defer c.Close()
	Must(c.SetDeadline(time.Now().Add(5 * time.Second)))
	req, err := http.NewRequest(method, u.Origin+path, bytes.NewReader(body))
	Must(err)
	req.Close = true
	if auth && u.session != "" {
		req.Header.Set("Authorization", "Bearer "+u.session)
	}
	if origin {
		req.Header.Set("Origin", u.Origin)
	}
	if csrf {
		req.Header.Set("X-FileGate-UI", "1")
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	Must(req.Write(c))
	response, err := http.ReadResponse(bufio.NewReader(c), req)
	Must(err)
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	Must(err)
	return response.StatusCode, response.Header, raw
}
func StartUI(h *Harness) *UIClient {
	h.Start()
	status, value := h.Request("POST", "/v1/ui/bootstrap", Object{}, nil, nil)
	h.Check("bootstrap_received", status == 200)
	target, err := url.Parse(Str(value, "url"))
	Must(err)
	h.Check("bootstrap_loopback_ephemeral", target.Scheme == "http" && target.Hostname() == "127.0.0.1" && target.Port() != "" && target.Path == "/" && len(target.Fragment) == 64)
	u := &UIClient{H: h, Origin: "http://" + target.Host, bootstrap: target.Fragment}
	info, err := os.Stat(h.Socket)
	Must(err)
	h.Check("owner_only_uds", info.Mode().Perm() == 0600)
	return u
}
func (u *UIClient) Authenticate() {
	body := Encoded(Object{"token": u.bootstrap})
	status, headers, raw := u.Request("POST", "/ui/session", body, map[string]string{"Content-Type": "application/json"}, false, true, true)
	u.session = Str(Decode(raw), "session")
	u.H.Check("bootstrap_exchange_without_cookie", status == 200 && len(u.session) == 64 && headers.Get("Set-Cookie") == "")
}
func (u *UIClient) CheckLogs() {
	combined := bytes.Join(u.H.Logs, []byte{'\n'})
	u.H.Check("authentication_values_not_logged", (u.bootstrap == "" || !bytes.Contains(combined, []byte(u.bootstrap))) && (u.session == "" || !bytes.Contains(combined, []byte(u.session))))
}
func init() { Register("ui", runUI) }
func runUI(h *Harness) {
	h.Record["scope"] = "real owner-only UDS and loopback HTTP UI; no VM, external network, or GUI execution"
	h.Record["gui_executed"] = false
	h.Record["vm_executed"] = false
	input := []byte("FileGate synthetic UI input.\n")
	Write(filepath.Join(h.Out, "input.txt"), input)
	h.Record["input_sha256"] = Digest(input)
	u := StartUI(h)
	defer func() { h.Stop(false); u.CheckLogs() }()
	request := func(method, path string, body []byte, headers map[string]string) (int, http.Header, []byte) {
		return u.Request(method, path, body, headers, true, true, true)
	}
	status, headers, html := u.Request("GET", "/", nil, nil, false, false, true)
	h.Check("static_shell_and_security_headers", status == 200 && bytes.Contains(html, []byte(`lang="ja"`)) && bytes.Contains([]byte(headers.Get("Content-Security-Policy")), []byte("default-src 'none'")) && bytes.Contains([]byte(headers.Get("Content-Security-Policy")), []byte("frame-ancestors 'none'")) && headers.Get("Referrer-Policy") == "no-referrer" && headers.Get("Access-Control-Allow-Origin") == "")
	status, _, _ = u.Request("GET", "/v1/jobs", nil, nil, false, true, true)
	h.Check("read_requires_auth", status == 401)
	status, _, _ = request("POST", "/v1/ui/bootstrap", []byte("{}"), nil)
	h.Check("bootstrap_not_on_http", status != 200)
	authBody := Encoded(Object{"token": u.bootstrap})
	status, _, _ = u.Request("POST", "/ui/session", authBody, map[string]string{"Content-Type": "application/json", "Origin": "https://example.invalid"}, false, true, true)
	h.Check("bootstrap_rejects_foreign_origin", status == 403)
	u.Authenticate()
	status, _, _ = u.Request("POST", "/ui/session", authBody, map[string]string{"Content-Type": "application/json"}, false, true, true)
	h.Check("bootstrap_is_one_use", status == 401)
	for _, test := range []struct {
		name, method, path string
		headers            map[string]string
		auth, origin, csrf bool
		expected           int
	}{{"host_is_exact", "GET", "/v1/jobs", map[string]string{"Host": "localhost"}, true, true, true, 400}, {"origin_is_exact", "GET", "/v1/jobs", map[string]string{"Origin": "null"}, true, true, true, 403}, {"unsafe_requires_origin", "POST", "/ui/logout", nil, true, false, true, 403}, {"unsafe_requires_dedicated_header", "POST", "/ui/logout", nil, true, true, false, 403}, {"no_cors_preflight", "OPTIONS", "/v1/jobs", nil, false, true, true, 403}, {"no_host_path_intake", "POST", "/v1/jobs", map[string]string{"Content-Type": "application/json"}, true, true, true, 404}, {"unknown_query_rejected", "GET", "/v1/jobs?unexpected=1", nil, true, true, true, 400}, {"duplicate_query_rejected", "GET", "/v1/jobs?limit=1&limit=2", nil, true, true, true, 400}} {
		status, _, _ = u.Request(test.method, test.path, []byte("{}"), test.headers, test.auth, test.origin, test.csrf)
		h.Check(test.name, status == test.expected)
	}
	status, _, _ = request("POST", "/v1/prune", nil, nil)
	release, _, _ := request("POST", "/v1/releases", nil, nil)
	h.Check("no_policy_or_release_override", status == 404 && release == 404)
	status, _, raw := request("GET", "/v1/health", nil, nil)
	health := Decode(raw)
	h.Check("release_and_pass_remain_disabled", status == 200 && Get(health, "pass_enabled") == false && Get(health, "release_enabled") == false)
	metadata := Object{"source_kind": "upload", "idempotency_key": "ui_e2e_intake", "display_name": "synthetic.txt", "expected_type": "txt"}
	fields := map[string]string{"Content-Type": "application/octet-stream", "Idempotency-Key": "ui_e2e_intake", "X-FileGate-Metadata": base64.RawURLEncoding.EncodeToString(Encoded(metadata))}
	status, _, raw = request("POST", "/v1/jobs/file", input, fields)
	receipt := Decode(raw)
	id := Str(receipt, "job_id")
	h.Check("raw_file_intake_committed", status == 202 && Str(receipt, "intake_status") == "COMMITTED" && Bool(receipt, "current_input_checked") && Str(receipt, "input_receipt", "sha256") == Digest(input))
	status, _, raw = request("POST", "/v1/jobs/file", []byte("changed but not consumed"), fields)
	replay := Decode(raw)
	h.Check("retry_uses_original_intake", status == 200 && Str(replay, "job_id") == id && Bool(replay, "replayed") && Get(replay, "body_consumed") == false && Get(replay, "current_input_checked") == false)
	status, _, raw = request("GET", "/v1/jobs?limit=1", nil, nil)
	jobs := List(Decode(raw), "jobs")
	h.Check("list_page_reads_real_job", status == 200 && len(jobs) > 0 && Str(jobs[0], "job_id") == id)
	status, _, raw = request("GET", "/v1/jobs/"+id, nil, nil)
	job := Decode(raw)
	h.Check("detail_coverage_without_fake_pass", status == 200 && Str(job, "verdict") == "HOLD" && Get(job, "release", "eligible") == false && Get(job, "coverage", "required_checks_complete") == false)
	status, _, _ = request("POST", "/v1/jobs/"+id+"/attempts", nil, nil)
	h.Check("rescan_routes_to_backend", status == 200)
	status, _, _ = request("POST", "/v1/jobs/"+id+"/cancel", nil, nil)
	h.Check("cancel_routes_to_backend", status == 200)
	status, _, raw = request("POST", "/v1/jobs/url", Encoded(Object{"source_kind": "url", "url": "file:///synthetic", "expected_type": "txt", "idempotency_key": "ui_invalid_url"}), map[string]string{"Content-Type": "application/json", "Idempotency-Key": "ui_invalid_url"})
	h.Check("url_validation_without_network", status == 400 && ErrorCode(Decode(raw)) == "INVALID_URL")
	status, _, _ = request("POST", "/ui/logout", nil, nil)
	loggedOut, _, _ := request("GET", "/v1/jobs", nil, nil)
	h.Check("logout_invalidates_session", status == 200 && loggedOut == 401)
}
