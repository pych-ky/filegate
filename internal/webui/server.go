package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"filegate.local/filegate/internal/api"
	"filegate.local/filegate/internal/broker"
)

//go:embed index.html app.js app.css
var assets embed.FS

var jobRoute = regexp.MustCompile(`^/v1/jobs/job_[0-9a-f]{32}(/(attempts|cancel|release|releases))?$`)
var releaseRoute = regexp.MustCompile(`^/v1/releases/release_[0-9a-f]{32}(/abort)?$`)
var originalDeleteRoute = regexp.MustCompile(`^/ui/jobs/job_[0-9a-f]{32}/delete-original$`)

type Server struct {
	backend        http.Handler
	deleteOriginal func(context.Context, string) (broker.Job, error)
	server         *http.Server
	origin         string
	host           string
	mu             sync.Mutex
	boot           string
	bootEnd        time.Time
	session        string
	end            time.Time
}

func Start(backend http.Handler, deleteOriginal func(context.Context, string) (broker.Job, error)) (*Server, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("UI_START_FAILED")
	}
	s := &Server{backend: backend, deleteOriginal: deleteOriginal, host: listener.Addr().String()}
	s.origin = "http://" + s.host
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	s.server = &http.Server{Protocols: protocols, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 20, MaxReadFrameSize: 16 << 10,
		MaxReceiveBufferPerConnection: 64 << 10, MaxReceiveBufferPerStream: 4 << 10}, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 125 * time.Second,
		WriteTimeout: 130 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = s.server.Serve(listener) }()
	return s, nil
}

func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		return s.server.Close()
	}
	return nil
}

func token() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("UI_AUTH_UNAVAILABLE")
	}
	return hex.EncodeToString(value[:]), nil
}

// LocalHandler issues bootstrap URLs only through the owner-only service socket.
func (s *Server) LocalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ui/bootstrap" {
			s.backend.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != api.Host || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" {
			writeError(w, http.StatusBadRequest, "INVALID_UI_BOOTSTRAP")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32))
		if err != nil || (strings.TrimSpace(string(body)) != "{}" && len(body) != 0) {
			writeError(w, http.StatusBadRequest, "INVALID_UI_BOOTSTRAP")
			return
		}
		value, err := token()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "UI_AUTH_UNAVAILABLE")
			return
		}
		s.mu.Lock()
		s.boot, s.bootEnd = value, time.Now().Add(time.Minute)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"url": s.origin + "/#" + value})
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
	if r.URL.Path == "/v1/jobs/file" && r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
		controller := http.NewResponseController(w)
		if controller.EnableFullDuplex() != nil {
			writeError(w, http.StatusInternalServerError, "HTTP_STREAM_CONTROL_UNAVAILABLE")
			return
		}
		defer func() { _ = controller.SetReadDeadline(time.Now()) }()
	}
	if r.Host != s.host || r.URL.RawPath != "" || !validQuery(r) {
		writeError(w, http.StatusBadRequest, "INVALID_HOST_OR_PATH")
		return
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != s.origin) {
		writeError(w, http.StatusForbidden, "INVALID_ORIGIN")
		return
	}
	if r.Method != http.MethodGet && (r.Method != http.MethodPost || len(origins) != 1 ||
		len(r.Header.Values("X-FileGate-UI")) != 1 || r.Header.Get("X-FileGate-UI") != "1") {
		writeError(w, http.StatusForbidden, "CSRF_REJECTED")
		return
	}
	if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/app.css") {
		name, contentType := "index.html", "text/html; charset=utf-8"
		if r.URL.Path == "/app.js" {
			name, contentType = "app.js", "text/javascript; charset=utf-8"
		} else if r.URL.Path == "/app.css" {
			name, contentType = "app.css", "text/css; charset=utf-8"
		}
		body, _ := assets.ReadFile(name)
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
		return
	}
	if r.URL.Path == "/ui/session" && r.Method == http.MethodPost {
		s.authenticate(w, r)
		return
	}
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "UI_AUTH_REQUIRED")
		return
	}
	if r.URL.Path == "/ui/logout" && r.Method == http.MethodPost {
		s.mu.Lock()
		s.session = ""
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]bool{"signed_out": true})
		return
	}
	if originalDeleteRoute.MatchString(r.URL.Path) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32))
		if err != nil || (len(body) != 0 && strings.TrimSpace(string(body)) != "{}") {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		job, err := s.deleteOriginal(r.Context(), strings.Split(r.URL.Path, "/")[3])
		if err != nil {
			var denied *broker.Error
			if errors.As(err, &denied) {
				writeError(w, denied.Status, denied.Code)
			} else {
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			}
			return
		}
		writeJSON(w, http.StatusOK, job)
		return
	}
	allowed := (r.Method == http.MethodGet && (r.URL.Path == "/v1/health" || r.URL.Path == "/v1/jobs" || r.URL.Path == "/v1/release-destinations")) ||
		(r.Method == http.MethodPost && (r.URL.Path == "/v1/jobs/file" || r.URL.Path == "/v1/jobs/url"))
	if jobRoute.MatchString(r.URL.Path) {
		action := strings.HasSuffix(r.URL.Path, "/attempts") || strings.HasSuffix(r.URL.Path, "/cancel") || strings.HasSuffix(r.URL.Path, "/release")
		allowed = (!action && r.Method == http.MethodGet) || (action && r.Method == http.MethodPost)
	}
	if releaseRoute.MatchString(r.URL.Path) {
		allowed = (strings.HasSuffix(r.URL.Path, "/abort") && r.Method == http.MethodPost) ||
			(!strings.HasSuffix(r.URL.Path, "/abort") && r.Method == http.MethodGet)
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	forward := r.Clone(r.Context())
	forward.Host = api.Host
	forward.Header.Del("Authorization")
	if r.URL.Path == "/v1/jobs/file" {
		metadata := r.Header.Values("X-FileGate-Metadata")
		keys := r.Header.Values("Idempotency-Key")
		if len(metadata) != 1 || len(metadata[0]) > 8<<10 || len(keys) != 1 || keys[0] == "" {
			writeError(w, http.StatusBadRequest, "INVALID_METADATA")
			return
		}
		body, err := base64.RawURLEncoding.Strict().DecodeString(metadata[0])
		var identity struct {
			Key string `json:"idempotency_key"`
		}
		if err != nil || json.Unmarshal(body, &identity) != nil || identity.Key != keys[0] {
			writeError(w, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY")
			return
		}
		forward.URL.Path = "/v1/uploads"
		forward.Header.Set(api.MetadataHeader, metadata[0])
	} else if strings.HasSuffix(r.URL.Path, "/attempts") {
		forward.URL.Path = strings.TrimSuffix(r.URL.Path, "/attempts") + "/rescan"
	}
	s.backend.ServeHTTP(w, forward)
}

func validQuery(r *http.Request) bool {
	if r.URL.RawQuery == "" {
		return true
	}
	if r.Method != http.MethodGet || (r.URL.Path != "/v1/jobs" && !(jobRoute.MatchString(r.URL.Path) && strings.HasSuffix(r.URL.Path, "/releases"))) || len(r.URL.RawQuery) > 512 {
		return false
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	for key, items := range values {
		if len(items) != 1 {
			return false
		}
		switch key {
		case "state":
			if r.URL.Path != "/v1/jobs" || !broker.ValidListState(items[0]) {
				return false
			}
		case "cursor":
			if len(items[0]) == 0 || len(items[0]) > 256 {
				return false
			}
		case "limit":
			number, err := strconv.Atoi(items[0])
			if err != nil || number < 1 || number > 100 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusBadRequest, "INVALID_UI_AUTH")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128))
	open, err := decoder.Token()
	key, keyErr := decoder.Token()
	var value string
	valueErr := decoder.Decode(&value)
	close, closeErr := decoder.Token()
	_, endErr := decoder.Token()
	if err != nil || keyErr != nil || valueErr != nil || closeErr != nil || endErr != io.EOF || open != json.Delim('{') || key != "token" || close != json.Delim('}') || len(value) != 64 {
		writeError(w, http.StatusBadRequest, "INVALID_UI_AUTH")
		return
	}
	session, err := token()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "UI_AUTH_UNAVAILABLE")
		return
	}
	s.mu.Lock()
	valid := s.boot != "" && time.Now().Before(s.bootEnd) && subtle.ConstantTimeCompare([]byte(value), []byte(s.boot)) == 1
	if valid {
		s.boot = ""
		s.session, s.end = session, time.Now().Add(8*time.Hour)
	}
	s.mu.Unlock()
	if !valid {
		writeError(w, http.StatusUnauthorized, "UI_AUTH_REQUIRED")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session": session})
}

func (s *Server) authorized(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return false
	}
	value := strings.TrimPrefix(values[0], "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session != "" && time.Now().Before(s.end) && subtle.ConstantTimeCompare([]byte(value), []byte(s.session)) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"schema_version": "4", "error": map[string]string{"code": code}})
}
