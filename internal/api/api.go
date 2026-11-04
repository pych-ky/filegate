package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"filegate.local/filegate/internal/acceptance"
	"filegate.local/filegate/internal/broker"
)

const (
	Host             = "filegate"
	MetadataHeader   = "FileGate-Metadata"
	maxJSONBytes     = 64 << 10
	maxMetadataBytes = 8 << 10
)

type handler struct {
	broker *broker.Broker
}

type uploadBody struct {
	io.ReadCloser
	controller *http.ResponseController
	complete   atomic.Bool
	closeOnce  sync.Once
	closeErr   error
}

func (body *uploadBody) Read(buffer []byte) (int, error) {
	n, err := body.ReadCloser.Read(buffer)
	if err == io.EOF {
		body.complete.Store(true)
	}
	return n, err
}

func (body *uploadBody) Close() error {
	body.closeOnce.Do(func() {
		// キャンセル時にBody.Closeが停止中のReadを待ち続けることを防ぐ。
		if !body.complete.Load() {
			body.closeErr = body.controller.SetReadDeadline(time.Now())
		}
		closeErr := body.ReadCloser.Close()
		if body.closeErr == nil {
			body.closeErr = closeErr
		}
	})
	return body.closeErr
}

type errorResponse struct {
	SchemaVersion string     `json:"schema_version"`
	Error         errorValue `json:"error"`
}

type errorValue struct {
	Code    string `json:"code"`
	Receipt any    `json:"receipt,omitempty"`
}

func New(b *broker.Broker) http.Handler {
	return &handler{broker: b}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/v1/uploads" && r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
		// 再送や要求拒否でも、応答前に未読のアップロード本文をdrainさせない。
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			writeError(w, http.StatusInternalServerError, "HTTP_STREAM_CONTROL_UNAVAILABLE", nil)
			return
		}
		// Goの応答後Body.Closeによる追加のネットワーク読取りも停止する。
		defer func() { _ = controller.SetReadDeadline(time.Now()) }()
	}
	if r.Host != Host {
		writeError(w, http.StatusBadRequest, "INVALID_HOST", nil)
		return
	}
	history := strings.HasPrefix(r.URL.Path, "/v1/jobs/") && strings.HasSuffix(r.URL.Path, "/releases") && strings.Count(r.URL.Path, "/") == 4
	if r.URL.RawQuery != "" && (r.Method != http.MethodGet || (r.URL.Path != "/v1/jobs" && !history)) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
		return
	}
	switch r.URL.Path {
	case "/v1/health":
		if !method(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, http.StatusOK, struct {
			SchemaVersion            string   `json:"schema_version"`
			Stage0Passed             bool     `json:"stage0_passed"`
			CustomerOperationEnabled bool     `json:"customer_operation_enabled"`
			PassEnabled              bool     `json:"pass_enabled"`
			ReleaseEnabled           bool     `json:"release_enabled"`
			SupportedIntake          []string `json:"supported_intake"`
		}{SchemaVersion: "4", Stage0Passed: broker.Stage0Passed, PassEnabled: broker.Stage0Passed, ReleaseEnabled: broker.Stage0Passed,
			CustomerOperationEnabled: broker.Stage0Passed && acceptance.Stage3Completed,
			SupportedIntake:          []string{"local", "upload", "url"}})
	case "/v1/jobs":
		h.jobs(w, r)
	case "/v1/uploads":
		h.upload(w, r)
	case "/v1/jobs/url":
		h.submitURL(w, r)
	case "/v1/releases":
		h.release(w, r)
	case "/v1/release-destinations":
		h.releaseDestinations(w, r)
	case "/v1/prune":
		if !method(w, r, http.MethodPost) || !emptyRequest(w, r) {
			return
		}
		result, err := h.broker.Prune(r.Context())
		if !brokerError(w, err) {
			writeJSON(w, http.StatusOK, result)
		}
	default:
		if strings.HasPrefix(r.URL.Path, "/v1/releases/") {
			h.releaseState(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/release-destinations/") {
			h.releaseDestinations(w, r)
			return
		}
		h.job(w, r)
	}
}

func (h *handler) submitURL(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var request broker.Request
	if !jsonRequest(w, r, &request) {
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] == "" || (request.IdempotencyKey != "" && request.IdempotencyKey != keys[0]) {
		writeError(w, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY", nil)
		return
	}
	if request.SourceKind != "" && request.SourceKind != "url" {
		writeError(w, http.StatusBadRequest, "UNSUPPORTED_INTAKE", nil)
		return
	}
	request.IdempotencyKey = keys[0]
	request.SourceKind = "url"
	receipt, err := h.broker.Submit(r.Context(), request, nil)
	if !brokerError(w, err) {
		writeJSON(w, receipt.HTTPStatus, receipt)
	}
}

func (h *handler) jobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(r.URL.RawQuery) > 1024 {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
			return
		}
		for key, values := range query {
			if (key != "cursor" && key != "limit" && key != "state") || len(values) != 1 || values[0] == "" {
				writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
				return
			}
		}
		limit := 100
		if value := query.Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 100 {
				writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
				return
			}
		}
		page, err := h.broker.ListStatePage(r.Context(), query.Get("state"), query.Get("cursor"), limit)
		if brokerError(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, page)
	case http.MethodPost:
		var request broker.Request
		if !jsonRequest(w, r, &request) {
			return
		}
		if request.SourceKind != "local" {
			writeError(w, http.StatusBadRequest, "UNSUPPORTED_INTAKE", nil)
			return
		}
		receipt, err := h.broker.Submit(r.Context(), request, nil)
		if !brokerError(w, err) {
			writeJSON(w, receipt.HTTPStatus, receipt)
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", nil)
	}
}

func (h *handler) upload(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) || !contentType(w, r, "application/octet-stream") {
		return
	}
	metadata := r.Header.Values(MetadataHeader)
	if len(metadata) != 1 || len(metadata[0]) == 0 || len(metadata[0]) > maxMetadataBytes {
		writeError(w, http.StatusBadRequest, "INVALID_METADATA", nil)
		return
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(metadata[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_METADATA", nil)
		return
	}
	var request broker.Request
	if err := decodeJSON(bytes.NewReader(body), &request); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_METADATA", nil)
		return
	}
	if request.SourceKind != "upload" {
		writeError(w, http.StatusBadRequest, "UNSUPPORTED_INTAKE", nil)
		return
	}
	receipt, err := h.broker.Submit(r.Context(), request, &uploadBody{ReadCloser: r.Body, controller: http.NewResponseController(w)})
	if !brokerError(w, err) {
		writeJSON(w, receipt.HTTPStatus, receipt)
	}
}

func (h *handler) job(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/jobs/") {
		writeError(w, http.StatusNotFound, "NOT_FOUND", nil)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/jobs/"), "/")
	if parts[0] == "" || len(parts) > 2 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", nil)
		return
	}
	var job broker.Job
	var err error
	if len(parts) == 1 {
		if !method(w, r, http.MethodGet) {
			return
		}
		job, err = h.broker.Get(r.Context(), parts[0])
	} else {
		if parts[1] == "releases" {
			h.jobReleases(w, r, parts[0])
			return
		}
		if parts[1] == "release" {
			h.jobRelease(w, r, parts[0])
			return
		}
		if parts[1] != "cancel" && parts[1] != "rescan" {
			writeError(w, http.StatusNotFound, "NOT_FOUND", nil)
			return
		}
		if !method(w, r, http.MethodPost) || !emptyRequest(w, r) {
			return
		}
		if parts[1] == "cancel" {
			job, err = h.broker.Cancel(r.Context(), parts[0])
		} else {
			job, err = h.broker.Rescan(r.Context(), parts[0])
		}
	}
	if !brokerError(w, err) {
		writeJSON(w, http.StatusOK, job)
	}
}

func (h *handler) release(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var request struct {
		JobID          string `json:"job_id"`
		Destination    string `json:"destination"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if !jsonRequest(w, r, &request) {
		return
	}
	if request.JobID == "" || request.Destination == "" || request.IdempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
		return
	}
	receipt, err := h.broker.Release(r.Context(), request.JobID, request.Destination, request.IdempotencyKey)
	if !brokerError(w, err) {
		writeJSON(w, receipt.HTTPStatus, receipt)
	}
}

func method(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Method == expected {
		return true
	}
	w.Header().Set("Allow", expected)
	writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", nil)
	return false
}

func contentType(w http.ResponseWriter, r *http.Request, expected string) bool {
	values := r.Header.Values("Content-Type")
	if len(values) == 1 {
		mediaType, _, err := mime.ParseMediaType(values[0])
		if err == nil && mediaType == expected {
			return true
		}
	}
	writeError(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", nil)
	return false
}

func jsonRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	if !contentType(w, r, "application/json") {
		return false
	}
	if err := decodeJSON(http.MaxBytesReader(w, r.Body, maxJSONBytes), value); err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", nil)
		} else {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
		}
		return false
	}
	return true
}

func decodeJSON(reader io.Reader, value any) error {
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' || !utf8.Valid(body) {
		return errors.New("INVALID_JSON_OBJECT")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("TRAILING_JSON")
		}
		return err
	}
	return nil
}

func emptyRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return true
	}
	var empty struct{}
	return jsonRequest(w, r, &empty)
}

func brokerError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var failure *broker.Error
	if errors.As(err, &failure) {
		if failure.ReleaseReceipt != nil {
			writeError(w, failure.Status, failure.Code, failure.ReleaseReceipt)
		} else if failure.Receipt != nil {
			writeError(w, failure.Status, failure.Code, failure.Receipt)
		} else {
			writeError(w, failure.Status, failure.Code, nil)
		}
	} else {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", nil)
	}
	return true
}

func writeError(w http.ResponseWriter, status int, code string, receipt any) {
	writeJSON(w, status, errorResponse{"4", errorValue{code, receipt}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
