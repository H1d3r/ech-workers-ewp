//go:build android

package ewpmobile

import (
	"net"
	"strings"
	"time"
)

// splitCSV splits "a, b ,c" into ["a","b","c"], trimming whitespace
// and dropping empty entries. Used because gomobile cannot pass
// []string across the FFI boundary.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// pingTCP does a single 3-second-bounded TCP connect and returns the
// elapsed milliseconds. Used by TestLatency.
func pingTCP(addr string) (int, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return 0, err
	}
	_ = c.Close()
	return int(time.Since(start) / time.Millisecond), nil
}
