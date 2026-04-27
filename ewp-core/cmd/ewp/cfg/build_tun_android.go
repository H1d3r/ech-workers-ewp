//go:build android

package cfg

import (
	"errors"

	"ewp-core/engine"
)

// On Android the TUN device is owned by the system VpnService and
// surfaced through ewpmobile, not through cmd/ewp. Trying to build a
// TUN inbound from yaml in an android build is a configuration error.
func buildTUNInbound(_ InboundCfg) (engine.Inbound, error) {
	return nil, errors.New("tun inbound is not available on android (use ewpmobile bindings)")
}
