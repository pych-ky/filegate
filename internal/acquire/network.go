package acquire

import (
	"net"
	"net/http"
	"time"
)

func transport() *http.Transport {
	return newTransport(net.DefaultResolver.LookupNetIP, (&net.Dialer{Timeout: 30 * time.Second}).DialContext, nil)
}
