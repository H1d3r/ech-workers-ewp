package dns

import (
	"crypto/tls"

	"ewp-core/common/cabundle"
)

// dohTLSConfig returns the *tls.Config used by DoH HTTP clients.
// TLS 1.3 only, embedded Mozilla trust store (NOT system CAs, to
// resist enterprise MITM), PQ-hybrid CurvePreferences mirroring our
// v2 inner crypto.
//
// We do NOT depend on common/tls here because common/tls itself
// imports this package for its ECH bootstrap; both go through the
// leaf cabundle pkg instead.
func dohTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		RootCAs:    cabundle.MozillaPool(),
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}
}
