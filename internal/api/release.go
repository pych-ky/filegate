package api

import (
	"net/http"
	"strings"
)

func (h *handler) jobRelease(w http.ResponseWriter, r *http.Request, jobID string) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var request struct {
		DestinationID string `json:"destination_id"`
	}
	if !jsonRequest(w, r, &request) {
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] == "" {
		writeError(w, 400, "INVALID_IDEMPOTENCY_KEY", nil)
		return
	}
	receipt, err := h.broker.Release(r.Context(), jobID, request.DestinationID, keys[0])
	if !brokerError(w, err) {
		writeJSON(w, receipt.HTTPStatus, receipt)
	}
}

func (h *handler) releaseState(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/releases/"), "/")
	if parts[0] == "" || len(parts) > 2 {
		writeError(w, 404, "NOT_FOUND", nil)
		return
	}
	if len(parts) == 1 {
		if !method(w, r, http.MethodGet) {
			return
		}
		receipt, err := h.broker.GetRelease(r.Context(), parts[0])
		if !brokerError(w, err) {
			writeJSON(w, 200, receipt)
		}
		return
	}
	if parts[1] != "abort" {
		writeError(w, 404, "NOT_FOUND", nil)
		return
	}
	if !method(w, r, http.MethodPost) || !emptyRequest(w, r) {
		return
	}
	receipt, err := h.broker.AbortRelease(r.Context(), parts[0])
	if !brokerError(w, err) {
		writeJSON(w, receipt.HTTPStatus, receipt)
	}
}

func (h *handler) releaseDestinations(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/release-destinations" {
		if !method(w, r, http.MethodGet) {
			return
		}
		destinations, err := h.broker.ReleaseDestinations(r.Context())
		if !brokerError(w, err) {
			writeJSON(w, 200, map[string]any{"schema_version": "4", "destinations": destinations})
		}
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/release-destinations/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "disable" {
		writeError(w, 404, "NOT_FOUND", nil)
		return
	}
	if !method(w, r, http.MethodPost) || !emptyRequest(w, r) {
		return
	}
	destination, err := h.broker.DisableReleaseDestination(r.Context(), parts[0])
	if !brokerError(w, err) {
		writeJSON(w, 200, map[string]any{"schema_version": "4", "destination": destination})
	}
}
