module ewp-core

go 1.24.0

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.1
	github.com/quic-go/quic-go v0.59.0
	github.com/xtaci/smux v1.5.53
	golang.org/x/crypto v0.47.0
	golang.org/x/net v0.49.0
	golang.org/x/sys v0.40.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	google.golang.org/grpc v1.69.0-dev
	google.golang.org/protobuf v1.36.0
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
)

// 排除旧版本的 genproto（防止依赖冲突）
exclude google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f
