package acquire

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"strconv"
	"strings"
)

const maxHeaderBytes = 64 << 10

// Inspect HTTP/1 headers before net/http removes conflicting framing fields.
type headerGuard struct {
	*tls.Conn
	reader      *bufio.Reader
	pending     *bytes.Reader
	headersDone bool
	headerBytes int
}

func guardHeaders(conn *tls.Conn) *headerGuard {
	return &headerGuard{Conn: conn, reader: bufio.NewReaderSize(conn, maxHeaderBytes)}
}

func (g *headerGuard) Read(p []byte) (int, error) {
	if g.pending != nil && g.pending.Len() > 0 {
		return g.pending.Read(p)
	}
	if g.headersDone {
		return g.reader.Read(p)
	}
	var raw bytes.Buffer
	for {
		line, err := g.reader.ReadSlice('\n')
		if err != nil {
			return 0, err
		}
		g.headerBytes += len(line)
		if g.headerBytes > maxHeaderBytes || !bytes.HasSuffix(line, []byte("\r\n")) {
			return 0, Error("DOWNLOAD_FRAMING_UNSUPPORTED")
		}
		raw.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	code, err := inspectHeader(raw.Bytes())
	if err != nil {
		return 0, err
	}
	g.headersDone = code >= 200 || code == 101
	g.pending = bytes.NewReader(raw.Bytes())
	return g.pending.Read(p)
}

func inspectHeader(raw []byte) (int, error) {
	lines := strings.Split(string(raw), "\r\n")
	status := strings.SplitN(lines[0], " ", 3)
	if len(status) < 2 || status[0] != "HTTP/1.1" && status[0] != "HTTP/1.0" || len(status[1]) != 3 {
		return 0, Error("DOWNLOAD_FRAMING_UNSUPPORTED")
	}
	code, err := strconv.Atoi(status[1])
	if err != nil || code < 100 {
		return 0, Error("DOWNLOAD_FRAMING_UNSUPPORTED")
	}
	cl, te := false, false
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return 0, Error("DOWNLOAD_FRAMING_UNSUPPORTED")
		}
		for _, c := range name {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return 0, Error("DOWNLOAD_FRAMING_UNSUPPORTED")
			}
		}
		cl = cl || strings.EqualFold(name, "content-length")
		te = te || strings.EqualFold(name, "transfer-encoding")
	}
	if cl && te {
		return 0, Error("DOWNLOAD_FRAMING_UNSUPPORTED")
	}
	return code, nil
}
