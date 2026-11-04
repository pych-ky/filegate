package api

import (
	"net/http"
	"net/url"
	"strconv"
)

func (h *handler) jobReleases(w http.ResponseWriter, r *http.Request, jobID string) {
	if !method(w, r, http.MethodGet) {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 1024 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", nil)
		return
	}
	for key, values := range query {
		if (key != "cursor" && key != "limit") || len(values) != 1 || values[0] == "" {
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
	page, err := h.broker.JobReleases(r.Context(), jobID, query.Get("cursor"), limit)
	if !brokerError(w, err) {
		writeJSON(w, http.StatusOK, page)
	}
}
