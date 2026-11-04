package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
)

func runUI(client *http.Client, args []string) int {
	if len(args) != 0 {
		return failure("INVALID_ARGUMENT")
	}
	body, status, err := call(context.Background(), client, http.MethodPost, "/v1/ui/bootstrap", struct{}{})
	var response struct {
		URL string `json:"url"`
	}
	if err != nil || status != http.StatusOK || strictDecode(body, &response) != nil {
		return failure("UI_UNAVAILABLE")
	}
	target, err := url.Parse(response.URL)
	if err != nil || target.Scheme != "http" || target.Hostname() != "127.0.0.1" || target.Path != "/" || target.RawQuery != "" || target.User != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(target.Fragment) {
		return failure("INVALID_UI_ENDPOINT")
	}
	if _, _, err := net.SplitHostPort(target.Host); err != nil || target.Port() == "" {
		return failure("INVALID_UI_ENDPOINT")
	}
	if !openUI(response.URL) {
		return failure("UI_OPEN_FAILED")
	}
	return emit(json.RawMessage(`{"opened":true}`), http.StatusOK, nil)
}
