//go:build android

package ewpmobile

import (
	"fmt"
	"strings"
)

// parseConfigUUID accepts an EWP v2 UUID in either canonical
// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" form or as a bare 32-char
// hex string and returns the 16-byte representation.
func parseConfigUUID(s string) ([16]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return [16]byte{}, fmt.Errorf("uuid: want 32 hex chars, got %d", len(clean))
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		hi, err := hexNib(clean[i*2])
		if err != nil {
			return [16]byte{}, err
		}
		lo, err := hexNib(clean[i*2+1])
		if err != nil {
			return [16]byte{}, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNib(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("uuid: bad hex char %q", c)
}
