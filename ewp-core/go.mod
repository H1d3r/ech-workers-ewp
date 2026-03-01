module ewp-core

go 1.25.5

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.1
	github.com/quic-go/quic-go v0.59.0
	github.com/xtaci/smux v1.5.53
	golang.org/x/crypto v0.48.0
	golang.org/x/mobile v0.0.0-20260217195705-b56b3793a9c4
	golang.org/x/net v0.50.0
	golang.org/x/sys v0.41.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.8
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
)

// 排除旧版本的 genproto（防止依赖冲突）
exclude google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f
