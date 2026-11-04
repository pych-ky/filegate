package acquire

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const MaxBytes int64 = 250 << 20

type Error string

func (e Error) Error() string { return string(e) }

var deniedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.Zone() != "" || addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) {
		return false
	}
	for _, prefix := range deniedNetworks {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func ValidateURL(raw string) error {
	if len(raw) == 0 || len(raw) > 8192 || strings.ContainsAny(raw, "\\\r\n\t ") {
		return Error("INVALID_URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host == "" || u.Port() != "" && u.Port() != "443" {
		return Error("INVALID_URL")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if !publicAddress(addr) {
			return Error("DOWNLOAD_DESTINATION_DENIED")
		}
		return nil
	}
	if len(host) > 253 || strings.HasSuffix(u.Host, ":") {
		return Error("INVALID_URL")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Error("INVALID_URL")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return Error("INVALID_URL")
			}
		}
	}
	return nil
}

type idleConn struct{ net.Conn }

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func newTransport(lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error), roots *tls.Config) *http.Transport {
	t := &http.Transport{DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: true, MaxResponseHeaderBytes: maxHeaderBytes, ResponseHeaderTimeout: 30 * time.Second}
	t.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		// Transport detaches request deadlines before invoking this dialer.
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" {
			return nil, Error("DOWNLOAD_DESTINATION_DENIED")
		}
		addresses, err := lookup(ctx, "ip", host)
		if err != nil {
			return nil, connectionError(ctx, err, "DOWNLOAD_CONNECTION_FAILED")
		}
		if len(addresses) == 0 {
			return nil, Error("DOWNLOAD_CONNECTION_FAILED")
		}
		for _, addr := range addresses {
			if !publicAddress(addr) {
				return nil, Error("DOWNLOAD_DESTINATION_DENIED")
			}
		}
		// Connect to the checked address; TLS still verifies the original hostname.
		conn, err := dial(ctx, "tcp", net.JoinHostPort(addresses[0].String(), port))
		if err != nil {
			return nil, connectionError(ctx, err, "DOWNLOAD_CONNECTION_FAILED")
		}
		config := &tls.Config{}
		if roots != nil {
			config = roots.Clone()
		}
		config.ServerName, config.MinVersion, config.NextProtos = host, tls.VersionTLS12, []string{"h2", "http/1.1"}
		tlsConn := tls.Client(&idleConn{conn}, config)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, connectionError(ctx, err, "DOWNLOAD_TLS_FAILED")
		}
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			return tlsConn, nil
		}
		return guardHeaders(tlsConn), nil
	}
	return t
}

func connectionError(ctx context.Context, err error, fallback Error) error {
	result := normalizedError(ctx, err)
	if result == Error("DOWNLOAD_INCOMPLETE") {
		return fallback
	}
	return result
}

type Body struct {
	io.ReadCloser
	ContentType string
	Length      int64
	read        int64
	ctx         context.Context
	cancel      context.CancelFunc
	transport   *http.Transport
}

func Open(ctx context.Context, rawURL string) (*Body, error) {
	return open(ctx, rawURL, transport())
}

func open(ctx context.Context, rawURL string, t *http.Transport) (*Body, error) {
	if err := ValidateURL(rawURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	client := &http.Client{Transport: t, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return Error("DOWNLOAD_REDIRECT_LIMIT")
		}
		request.Header.Del("Referer")
		return ValidateURL(request.URL.String())
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, Error("INVALID_URL")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err == nil {
		err = validateResponse(response)
	}
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		result := normalizedError(ctx, err)
		cancel()
		t.CloseIdleConnections()
		return nil, result
	}
	return &Body{ReadCloser: response.Body, ContentType: response.Header.Get("Content-Type"), Length: response.ContentLength, ctx: ctx, cancel: cancel, transport: t}, nil
}

func validateResponse(response *http.Response) error {
	_, contentRange := response.Header["Content-Range"]
	encodings := response.Header.Values("Content-Encoding")
	switch {
	case response.StatusCode != http.StatusOK:
		return Error("DOWNLOAD_HTTP_STATUS")
	case contentRange || len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(encodings[0], "identity"):
		return Error("DOWNLOAD_FRAMING_UNSUPPORTED")
	case response.ContentLength > MaxBytes:
		return Error("LIMIT_EXCEEDED")
	case response.ProtoMajor == 1 && response.ContentLength < 0 && (len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked"):
		return Error("DOWNLOAD_FRAMING_UNSUPPORTED")
	case response.ProtoMajor != 1 && response.ProtoMajor != 2:
		return Error("DOWNLOAD_FRAMING_UNSUPPORTED")
	}
	return nil
}

func normalizedError(ctx context.Context, err error) error {
	var fixed Error
	if errors.As(err, &fixed) {
		return fixed
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return Error("DOWNLOAD_CANCELLED")
	}
	var timeout net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return Error("DOWNLOAD_TIMEOUT")
	}
	return Error("DOWNLOAD_INCOMPLETE")
}

func (b *Body) Read(p []byte) (int, error) {
	if b.read > MaxBytes {
		return 0, Error("LIMIT_EXCEEDED")
	}
	if int64(len(p)) > MaxBytes+1-b.read {
		p = p[:MaxBytes+1-b.read]
	}
	n, err := b.ReadCloser.Read(p)
	b.read += int64(n)
	if b.read > MaxBytes {
		return n, Error("LIMIT_EXCEEDED")
	}
	if err == io.EOF {
		if b.Length >= 0 && b.read != b.Length {
			return n, Error("DOWNLOAD_INCOMPLETE")
		}
		return n, io.EOF
	}
	if err != nil {
		return n, normalizedError(b.ctx, err)
	}
	return n, nil
}

func (b *Body) Close() error {
	b.cancel()
	err := b.ReadCloser.Close()
	b.transport.CloseIdleConnections()
	if err != nil {
		return Error("DOWNLOAD_INCOMPLETE")
	}
	return nil
}
