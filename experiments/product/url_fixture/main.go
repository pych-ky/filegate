package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
)

const body = "FileGate synthetic HTTPS intake fixture.\n"

func main() {
	var mu sync.Mutex
	counts := map[string]int{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path
		if name != "/ok" && name != "/hash" && name != "/broken" && name != "/status" {
			name = "unexpected"
		}
		mu.Lock()
		counts[name]++
		mu.Unlock()
		if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if name == "/status" || name == "unexpected" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "synthetic error body must not become an original")
			return
		}
		length := len(body)
		if name == "/broken" {
			length += 7
		}
		w.Header().Set("Content-Length", strconv.Itoa(length))
		io.WriteString(w, body)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	digest := sha256.Sum256([]byte(body))
	info := map[string]any{"address": server.Listener.Addr().String(), "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		"sha256": hex.EncodeToString(digest[:]), "byte_size": len(body), "body": body}
	if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
		server.Close()
		os.Exit(1)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	server.Close()
	mu.Lock()
	result, _ := json.Marshal(map[string]any{"counts": counts})
	mu.Unlock()
	fmt.Println(string(result))
}
