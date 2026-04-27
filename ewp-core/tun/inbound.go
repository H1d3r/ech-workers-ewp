package tun

import (
	"context"

	"ewp-core/engine"
)

// AsInbound wraps the TUN device as an engine.Inbound.
//
// Usage:
//
//	t, _ := tun.New(cfg)
//	_ = t.Setup()
//	eng := engine.New(&engine.StaticRouter{Tag: "myout"})
//	_ = eng.AddOutbound(...)
//	_ = eng.AddInbound(t.AsInbound("tun"))
//	_ = eng.Start(ctx)
func (t *TUN) AsInbound(tag string) engine.Inbound {
	if tag == "" {
		tag = "tun"
	}
	return &tunInbound{tun: t, tag: tag}
}

// Handler exposes the underlying *Handler for advanced wiring (e.g.
// callers that want to install an Engine via BindEngine before
// starting the gVisor stack).
func (t *TUN) Handler() *Handler { return t.handler }

type tunInbound struct {
	tun *TUN
	tag string
}

func (i *tunInbound) Tag() string { return i.tag }

func (i *tunInbound) Start(ctx context.Context, h engine.InboundHandler) error {
	i.tun.handler.BindEngine(h)
	return i.tun.Start()
}

func (i *tunInbound) Close() error {
	i.tun.handler.Close()
	return i.tun.Close()
}
