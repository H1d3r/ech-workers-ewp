package cfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoad_FullExample exercises every yaml field present in the
// canonical examples/ tree, ensuring the schema parses without
// surprises.
func TestLoad_FullExample(t *testing.T) {
	yaml := `
inbounds:
  - tag: tun
    type: tun
    tun:
      address: 198.18.0.1/24
      mtu: 1500
      dns: ["198.18.0.2", "fc00::2"]
      fake_ip: true
      bypass_server: vps.example.com:443
  - tag: socks
    type: socks5
    listen: "127.0.0.1:1080"
    users:
      alice: "s3cret"

outbounds:
  - tag: my-vps
    type: ewpclient
    uuid: "01020304-0506-0708-090a-0b0c0d0e0f10"
    transport:
      kind: websocket
      url: "wss://vps.example.com/ewp"
      sni: "vps.example.com"
      ech: true
  - tag: out
    type: direct

router:
  default: my-vps

dns:
  client:
    mode: fake-ip
  server:
    upstream:
      servers: ["https://1.1.1.1/dns-query"]
      cache_size: 4096
      worker_pool: 4
      min_ttl_sec: 30
      max_ttl_sec: 1800

ech:
  bootstrap_doh:
    servers: ["https://1.1.1.1/dns-query"]

stun:
  servers: ["stun.cloudflare.com:3478"]
`
	path := writeTemp(t, "cfg.yaml", yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(f.Inbounds); got != 2 {
		t.Errorf("inbounds = %d, want 2", got)
	}
	if got := len(f.Outbounds); got != 2 {
		t.Errorf("outbounds = %d, want 2", got)
	}
	if got := f.Router.Default; got != "my-vps" {
		t.Errorf("router.default = %q, want my-vps", got)
	}
	if got := f.DNS.Client.Mode; got != "fake-ip" {
		t.Errorf("dns.client.mode = %q", got)
	}
	if got := len(f.DNS.Server.Upstream.Servers); got != 1 {
		t.Errorf("dns.server.upstream.servers = %d", got)
	}
	if got := len(f.ECH.BootstrapDoH.Servers); got != 1 {
		t.Errorf("ech.bootstrap_doh.servers = %d", got)
	}
	if got := len(f.STUN.Servers); got != 1 {
		t.Errorf("stun.servers = %d", got)
	}
	if got := f.Inbounds[0].TUN.BypassServer; got != "vps.example.com:443" {
		t.Errorf("tun.bypass_server = %q", got)
	}
	if got := f.Inbounds[1].Users["alice"]; got != "s3cret" {
		t.Errorf("socks5 user not parsed: %q", got)
	}
}

// TestLoad_DefaultsToFirstOutbound ensures that an unspecified router
// default falls back to the first outbound's tag.
func TestLoad_DefaultsToFirstOutbound(t *testing.T) {
	yaml := `
inbounds:
  - tag: a
    type: socks5
    listen: 127.0.0.1:1
outbounds:
  - tag: foo
    type: direct
`
	path := writeTemp(t, "default.yaml", yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := f.Router.Default; got != "foo" {
		t.Errorf("router.default = %q, want foo", got)
	}
}

// TestLoad_RequiresInbound asserts that an inbound-less config is rejected.
func TestLoad_RequiresInbound(t *testing.T) {
	yaml := `
outbounds:
  - tag: foo
    type: direct
`
	path := writeTemp(t, "no-inbound.yaml", yaml)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "inbound") {
		t.Errorf("got %v, want error mentioning inbound", err)
	}
}

// TestLoad_RequiresOutbound asserts that an outbound-less config is rejected.
func TestLoad_RequiresOutbound(t *testing.T) {
	yaml := `
inbounds:
  - tag: a
    type: socks5
    listen: 127.0.0.1:1
`
	path := writeTemp(t, "no-out.yaml", yaml)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "outbound") {
		t.Errorf("got %v, want error mentioning outbound", err)
	}
}

// TestParseUUID covers the two accepted forms (with and without
// dashes) plus the common error path.
func TestParseUUID(t *testing.T) {
	canonical := "01020304-0506-0708-090a-0b0c0d0e0f10"
	bare := "0102030405060708090a0b0c0d0e0f10"
	cases := []struct {
		in   string
		want byte // first byte
		err  bool
	}{
		{canonical, 0x01, false},
		{bare, 0x01, false},
		{"too-short", 0, true},
		{"01020304-XX06-0708-090a-0b0c0d0e0f10", 0, true},
	}
	for _, c := range cases {
		got, err := parseUUID(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseUUID(%q): want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUUID(%q): %v", c.in, err)
			continue
		}
		if got[0] != c.want {
			t.Errorf("parseUUID(%q): first byte = 0x%02x, want 0x%02x", c.in, got[0], c.want)
		}
	}
}

// TestBuildAsyncResolver returns nil for empty servers and a real
// resolver otherwise.
func TestBuildAsyncResolver(t *testing.T) {
	if BuildAsyncResolver(UpstreamDoHCfg{}) != nil {
		t.Error("expected nil for empty servers")
	}
	r := BuildAsyncResolver(UpstreamDoHCfg{
		Servers:    []string{"https://1.1.1.1/dns-query"},
		CacheSize:  16,
		WorkerPool: 1,
	})
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
	_ = r.Close()
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}
