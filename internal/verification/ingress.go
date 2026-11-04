package verification

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func init() { Register("ingress-protocol", runIngress) }
func VerifyBinaryProof(h *Harness) {
	h.Check("binary_proof_supplied", h.BinaryProof != "")
	proof := ReadJSON(h.BinaryProof)
	var build Object
	for _, row := range List(proof, "builds") {
		if Str(row, "name") == "normal" {
			build = Map(row)
			break
		}
	}
	h.Check("fixed_binary_proof", Bool(proof, "passed") && build != nil && Int(build, "exit_code") == 0 && FileDigest(h.Binary) == Str(build, "binary_sha256"))
	Write(filepath.Join(h.Out, "binary-proof.json"), Read(h.BinaryProof))
	h.Record["binary_proof_sha256"] = FileDigest(h.BinaryProof)
}
func probe(connect func() net.Conn, request []byte) ([]byte, bool) {
	c := connect()
	defer c.Close()
	_, err := c.Write(request)
	Must(err)
	body := []byte{}
	buffer := make([]byte, 4096)
	for len(body) <= 8192 {
		n, err := c.Read(buffer)
		body = append(body, buffer[:n]...)
		if err == io.EOF {
			return body, true
		}
		Must(err)
	}
	return body, false
}

func h2Settings(h *Harness, name string, connect func() net.Conn) {
	c := connect()
	defer c.Close()
	ping := []byte("FGH2PING")
	preface := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}...)
	preface = append(preface, []byte{0, 0, 8, 6, 0, 0, 0, 0, 0}...)
	_, err := c.Write(append(preface, ping...))
	Must(err)
	settings := Object{}
	window := uint32(65535)
	received := false
	settingsAcknowledged, pingAcknowledged := false, false
	for count := 0; count < 8; count++ {
		header := make([]byte, 9)
		_, err = io.ReadFull(c, header)
		Must(err)
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		h.Check(name+"_frame_read_bounded", length <= 16<<10)
		body := make([]byte, length)
		_, err = io.ReadFull(c, body)
		Must(err)
		stream := binary.BigEndian.Uint32(header[5:]) & 0x7fffffff
		h.Check(name+"_expected_initial_control_frame", header[3] == 4 || header[3] == 6 || header[3] == 8)
		switch header[3] {
		case 4:
			if header[4]&1 == 0 {
				h.Check(name+"_settings_frame", stream == 0 && length%6 == 0)
				for offset := 0; offset < length; offset += 6 {
					id, value := binary.BigEndian.Uint16(body[offset:]), binary.BigEndian.Uint32(body[offset+2:])
					switch id {
					case 3:
						settings["max_concurrent_streams"] = value
					case 4:
						settings["stream_receive_window"] = value
					case 5:
						settings["max_read_frame_size"] = value
					}
				}
				received = true
				_, err = c.Write([]byte{0, 0, 0, 4, 1, 0, 0, 0, 0})
				Must(err)
			} else {
				h.Check(name+"_peer_settings_acknowledged", stream == 0 && length == 0)
				settingsAcknowledged = true
			}
		case 6:
			h.Check(name+"_ping_roundtrip", header[4] == 1 && stream == 0 && bytes.Equal(body, ping))
			pingAcknowledged = true
		case 8:
			h.Check(name+"_initial_connection_window_frame", stream == 0 && length == 4)
			window += binary.BigEndian.Uint32(body) & 0x7fffffff
		}
		if received && settingsAcknowledged && pingAcknowledged {
			break
		}
	}
	settings["connection_receive_window"] = window
	settings["configured_connection_receive_buffer"] = 64 << 10
	settings["control_roundtrip_complete"] = settingsAcknowledged && pingAcknowledged
	// Go retains the one-byte difference from the initial window until inflow refresh.
	settings["unadvertised_initial_connection_credit"] = (64 << 10) - window
	h.Record[name+"_http2_settings"] = settings
	h.Check(name+"_http2_connection_and_stream_limits", received && settingsAcknowledged && pingAcknowledged && Int(settings, "max_concurrent_streams") == 20 && Int(settings, "stream_receive_window") == 4<<10 && Int(settings, "max_read_frame_size") == 16<<10 && window == 65535)
}
func h2Requests(h *Harness, name, origin, bootstrap string, connect func() net.Conn) {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols, MaxConnsPerHost: 1, HTTP2: &http.HTTP2Config{StrictMaxConcurrentRequests: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		c := connect()
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	session := ""
	observations := []Object{}
	request := func(label, method, path string, value any, headers map[string]string, auth bool) (int, Object) {
		var body []byte
		if value != nil {
			body = Encoded(value)
		}
		req, err := http.NewRequest(method, origin+path, bytes.NewReader(body))
		Must(err)
		if value != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if name == "loopback" {
			req.Header.Set("Origin", origin)
			req.Header.Set("X-FileGate-UI", "1")
			if auth {
				req.Header.Set("Authorization", "Bearer "+session)
			}
		}
		for key, value := range headers {
			if key == "Host" {
				req.Host = value
			} else {
				req.Header.Set(key, value)
			}
		}
		response, err := client.Do(req)
		Must(err)
		raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		Must(err)
		Must(response.Body.Close())
		decoded := Decode(raw)
		observations = append(observations, Object{"probe": label, "protocol": response.Proto, "status": response.StatusCode, "error_code": ErrorCode(decoded), "bytes": len(raw)})
		h.Record[name+"_http2_requests"] = observations
		h.Check(name+"_"+label+"_http2", response.ProtoMajor == 2)
		return response.StatusCode, decoded
	}
	if name == "loopback" {
		status, value := request("health_without_session", "GET", "/v1/health", nil, nil, false)
		h.Check("loopback_http2_auth_required", status == 401 && ErrorCode(value) == "UI_AUTH_REQUIRED")
		status, value = request("session_exchange", "POST", "/ui/session", Object{"token": bootstrap}, nil, false)
		session = Str(value, "session")
		h.Check("loopback_http2_bootstrap_exchange", status == 200 && len(session) == 64)
	}
	status, health := request("health", "GET", "/v1/health", nil, nil, true)
	h.Check(name+"_http2_health_gates_closed", status == 200 && GatesClosed(health))
	status, value := request("invalid_host", "GET", "/v1/health", nil, map[string]string{"Host": "untrusted"}, true)
	expectedHostError := "INVALID_HOST"
	if name == "loopback" {
		expectedHostError = "INVALID_HOST_OR_PATH"
	}
	h.Check(name+"_http2_invalid_host_rejected", status == 400 && ErrorCode(value) == expectedHostError)
	if name == "uds" {
		status, value = request("unknown_json_field", "POST", "/v1/jobs", Object{"unknown": 1}, nil, true)
		h.Check("uds_http2_strict_json", status == 400 && ErrorCode(value) == "INVALID_REQUEST")
	} else {
		status, value = request("foreign_origin", "GET", "/v1/health", nil, map[string]string{"Origin": "https://example.invalid"}, true)
		h.Check("loopback_http2_foreign_origin_rejected", status == 403 && ErrorCode(value) == "INVALID_ORIGIN")
		status, value = request("missing_csrf_header", "POST", "/ui/logout", nil, map[string]string{"X-FileGate-UI": ""}, true)
		h.Check("loopback_http2_csrf_rejected", status == 403 && ErrorCode(value) == "CSRF_REJECTED")
		status, value = request("invalid_url", "POST", "/v1/jobs/url", Object{"source_kind": "url", "url": "file:///synthetic", "expected_type": "txt", "idempotency_key": "h2-invalid-url"}, map[string]string{"Idempotency-Key": "h2-invalid-url"}, true)
		h.Check("loopback_http2_url_rejected_before_intake", status == 400 && ErrorCode(value) == "INVALID_URL")
	}
	if session != "" {
		h.Record["http2_session_values_not_recorded"] = true
	}
}
func runIngress(h *Harness) {
	VerifyBinaryProof(h)
	h.Record["scope"] = "plaintext ingress protocol selection on UDS and loopback; no browser"
	h.Record["http2_ingress_enabled"] = true
	h.Record["not_demonstrated"] = []string{"HTTP/2 unread-body replay", "AV or release"}
	h.Record["prior_knowledge_http2"] = true
	h.Record["http2_stdlib_sources_sha256"] = Object{"http2.go": FileDigest(filepath.Join(runtime.GOROOT(), "src/net/http/http2.go")), "http2_server.go": FileDigest(filepath.Join(runtime.GOROOT(), "src/net/http/internal/http2/server.go")), "http2_flow.go": FileDigest(filepath.Join(runtime.GOROOT(), "src/net/http/internal/http2/flow.go")), "transport.go": FileDigest(filepath.Join(runtime.GOROOT(), "src/net/http/transport.go"))}
	health := h.Start()
	h.Check("gates_closed", Get(health, "stage0_passed") == false && Get(health, "pass_enabled") == false && Get(health, "release_enabled") == false)
	status, bootstrap := h.Request("POST", "/v1/ui/bootstrap", Object{}, nil, nil)
	h.Check("loopback_endpoint_obtained", status == 200)
	endpoint, err := url.Parse(Str(bootstrap, "url"))
	Must(err)
	observations := []Object{}
	for _, target := range []struct {
		name, host string
		connect    func() net.Conn
	}{{"uds", "filegate", h.Connect}, {"loopback", endpoint.Host, func() net.Conn {
		c, err := net.DialTimeout("tcp", endpoint.Host, 3*time.Second)
		Must(err)
		Must(c.SetDeadline(time.Now().Add(3 * time.Second)))
		return c
	}}} {
		h2Settings(h, target.name, target.connect)
		origin := "http://filegate"
		if target.name == "loopback" {
			origin = "http://" + endpoint.Host
		}
		h2Requests(h, target.name, origin, endpoint.Fragment, target.connect)
		request := []byte("GET /v1/health HTTP/1.1\r\nHost: " + target.host + "\r\nConnection: Upgrade, HTTP2-Settings, close\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\n\r\n")
		raw, closed := probe(target.connect, request)
		line := string(bytes.SplitN(raw, []byte("\r\n"), 2)[0])
		fields := strings.Fields(line)
		observations = append(observations, Object{"endpoint": target.name, "probe": "h2c_upgrade", "status_line": line, "bytes": len(raw), "connection_closed": closed})
		h.Record["responses"] = observations
		h.Check(target.name+"_h2c_not_upgraded", closed && len(raw) <= 8192 && strings.HasPrefix(line, "HTTP/1.1 ") && len(fields) > 1 && fields[1] != "101")
	}
	status, _ = h.Request("GET", "/v1/health", nil, nil, nil)
	h.Check("http1_remains_available", status == 200)
	counts := Object{}
	empty := true
	for _, name := range []string{"jobs", "objects", "reservations", "runtime_runs", "resource_pins", "scan_queue"} {
		rows := h.Query("SELECT count(*) FROM " + name)
		counts[name] = rows[0][0]
		empty = empty && rows[0][0] == int64(0)
	}
	h.Record["ledger"] = counts
	partial, err := os.ReadDir(filepath.Join(h.Data, "partial"))
	Must(err)
	objects, err := os.ReadDir(filepath.Join(h.Data, "objects"))
	Must(err)
	h.Check("no_intake_or_reservation", empty && len(partial) == 0 && len(objects) == 0)
	h.Stop(false)
	logs := 0
	for _, body := range h.Logs {
		logs += len(body)
	}
	h.Check("raw_service_output_empty", logs == 0)
}
