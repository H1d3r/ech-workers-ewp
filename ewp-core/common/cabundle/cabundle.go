// Package cabundle exposes the embedded Mozilla root CA bundle used
// by all of ewp-core's outbound TLS clients.
//
// It lives in its own leaf package (no other ewp-core imports) so
// that both common/tls and dns can use it without creating an
// import cycle: common/tls imports dns (for ECH bootstrap), so dns
// cannot in turn import common/tls — both go through cabundle
// instead.
package cabundle

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

//go:embed mozilla_cas.pem
var mozillaCAPEM []byte

var (
	once sync.Once
	pool *x509.CertPool
)

// MozillaPool returns the parsed Mozilla CA pool. The result is
// cached and shared across callers; do not mutate.
//
// Panics if the embedded PEM is unparseable; this is an immediate
// build/release error and should never reach a user.
func MozillaPool() *x509.CertPool {
	once.Do(func() {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(mozillaCAPEM) {
			panic("cabundle: failed to parse embedded mozilla_cas.pem")
		}
		pool = p
	})
	return pool
}

// PEM returns the raw PEM bytes for callers (e.g. tests) that need
// to AppendCertsFromPEM into a custom pool.
func PEM() []byte { return mozillaCAPEM }
