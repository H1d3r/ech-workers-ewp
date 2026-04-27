# HTTP/3 + gRPC-Web 实现方案

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                      完整请求链路                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Client (ewp-core-client)                                        │
│    ↓ HTTP/3 (QUIC)                                              │
│    ↓ ALPN: h3                                                   │
│    ↓ Content-Type: application/grpc-web+proto                   │
│    ↓                                                             │
│  CDN 边缘节点 (Cloudflare/Fastly)                                │
│    ↓ 自动 ALPN 协商                                              │
│    ├─→ 后端 ALPN: h2                                            │
│    │     → 转换为标准 gRPC                                       │
│    │     → Content-Type: application/grpc+proto                 │
│    │     → HTTP/2 帧格式                                         │
│    │                                                             │
│    └─→ 后端 ALPN: http/1.1                                      │
│          → 直接转发 gRPC-Web                                     │
│          → Content-Type: application/grpc-web+proto             │
│          → HTTP/1.1 分块传输                                     │
│          ↓                                                       │
│  Server (ewp-core-server)                                        │
│    ↓ 自动检测 Content-Type                                       │
│    ├─→ application/grpc+proto      → 标准 gRPC 处理              │
│    └─→ application/grpc-web+proto  → gRPC-Web 解码 → 标准处理   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 客户端实现

### 文件结构

```
ewp-core/transport/h3grpc/
├── transport.go       # 实现 transport.Transport 接口
├── conn.go           # 实现 transport.TunnelConn 接口
├── grpcweb.go        # gRPC-Web 帧编解码器
└── quic_dialer.go    # QUIC 连接池管理
```

### gRPC-Web Binary 格式

```
每个消息帧：
┌────────────┬──────────────┬──────────────────┐
│ Compressed │ Message-Len  │  Protobuf Data   │
│  (1 byte)  │  (4 bytes)   │   (variable)     │
└────────────┴──────────────┴──────────────────┘

Compressed: 0x00 = 未压缩, 0x01 = gzip
Length:     uint32 大端序
Data:       标准 Protobuf 编码
```

### HTTP/3 请求格式

```http
POST /ProxyService/Tunnel HTTP/3
Host: cdn.example.com
Content-Type: application/grpc-web+proto
TE: trailers
User-Agent: grpc-web-go/1.0

[gRPC-Web Binary Frames]
```

### 关键代码接口

```go
// transport/h3grpc/transport.go
type Transport struct {
    serverAddr string
    serverIP   string
    uuid       [16]byte
    enableFlow bool
    enableECH  bool
    enablePQC  bool
    
    quicConfig  *quic.Config
    tlsConfig   *tls.Config
    http3Client *http.Client
}

func (t *Transport) Dial() (transport.TunnelConn, error) {
    // 1. 建立 HTTP/3 连接
    // 2. 发送 POST 请求到 /ServiceName/Tunnel
    // 3. 返回包装的 TunnelConn
}

// transport/h3grpc/conn.go
type Conn struct {
    request  *http.Request
    response *http.Response
    encoder  *GRPCWebEncoder
    decoder  *GRPCWebDecoder
    // ...
}

func (c *Conn) Connect(target string, initialData []byte) error {
    // 发送 EWP 协议的 Connect 请求
}

func (c *Conn) Read(buf []byte) (int, error) {
    // 读取并解码 gRPC-Web 帧
}

func (c *Conn) Write(data []byte) error {
    // 编码为 gRPC-Web 帧并发送
}

// transport/h3grpc/grpcweb.go
type GRPCWebEncoder struct {
    writer io.Writer
}

func (e *GRPCWebEncoder) Encode(data []byte) error {
    // [0x00][len:4][data]
    header := make([]byte, 5)
    header[0] = 0x00 // 未压缩
    binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
    e.writer.Write(header)
    e.writer.Write(data)
}

type GRPCWebDecoder struct {
    reader io.Reader
}

func (d *GRPCWebDecoder) Decode() ([]byte, error) {
    // 读取 5 字节头
    // 读取 payload
    // 返回数据
}
```

## 服务端实现

### 自适应 TLS 配置

```go
// cmd/server/main.go
tlsConfig := &tls.Config{
    NextProtos: []string{"h2", "http/1.1"}, // 支持两种 ALPN
    // ... 其他配置
}

// 根据协商结果，自动选择处理方式
```

### 统一的 HTTP Handler

```go
// internal/server/grpc_web_adapter.go
type GRPCWebAdapter struct {
    grpcServer *grpc.Server
}

func (a *GRPCWebAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    contentType := r.Header.Get("Content-Type")
    
    switch {
    case strings.HasPrefix(contentType, "application/grpc+proto"):
        // 标准 gRPC - 直接交给 grpc.Server
        a.grpcServer.ServeHTTP(w, r)
        
    case strings.HasPrefix(contentType, "application/grpc-web+proto"):
        // gRPC-Web - 解包后交给 grpc.Server
        a.handleGRPCWeb(w, r)
        
    default:
        http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
    }
}

func (a *GRPCWebAdapter) handleGRPCWeb(w http.ResponseWriter, r *http.Request) {
    // 1. 包装 Request Body：gRPC-Web → 标准 gRPC 格式
    unwrappedBody := &grpcWebUnwrapper{
        reader: r.Body,
    }
    r.Body = io.NopCloser(unwrappedBody)
    
    // 2. 包装 ResponseWriter：标准 gRPC → gRPC-Web 格式
    wrappedWriter := &grpcWebWrapper{
        ResponseWriter: w,
        flusher:        w.(http.Flusher),
    }
    
    // 3. 修改 Content-Type 为标准 gRPC
    r.Header.Set("Content-Type", "application/grpc+proto")
    
    // 4. 交给标准 gRPC Server 处理
    a.grpcServer.ServeHTTP(wrappedWriter, r)
}

// grpcWebUnwrapper 解包 gRPC-Web 请求
type grpcWebUnwrapper struct {
    reader io.Reader
}

func (u *grpcWebUnwrapper) Read(p []byte) (int, error) {
    // 读取 gRPC-Web 帧：[compressed][length:4][data]
    // 转换为标准 gRPC 帧：[compressed][length:4][data]
    // (格式其实一样，只需要透传)
    return u.reader.Read(p)
}

// grpcWebWrapper 包装 gRPC-Web 响应
type grpcWebWrapper struct {
    http.ResponseWriter
    flusher http.Flusher
    wroteHeader bool
}

func (w *grpcWebWrapper) Write(b []byte) (int, error) {
    if !w.wroteHeader {
        w.Header().Set("Content-Type", "application/grpc-web+proto")
        w.wroteHeader = true
    }
    n, err := w.ResponseWriter.Write(b)
    w.flusher.Flush()
    return n, err
}
```

### 服务端启动代码

```go
// cmd/server/main.go
func startUnifiedServer() {
    // 创建标准 gRPC Server
    grpcServer := grpc.NewServer(
        grpc.KeepaliveParams(keepalive.ServerParameters{
            Time: 60 * time.Second,
        }),
    )
    
    // 注册服务
    pb.RegisterProxyServiceServer(grpcServer, &proxyServer{})
    
    // 创建 gRPC-Web 适配器
    adapter := &GRPCWebAdapter{
        grpcServer: grpcServer,
    }
    
    // 创建 HTTP/2 Server（同时支持 HTTP/1.1）
    httpServer := &http.Server{
        Addr:      ":" + port,
        Handler:   adapter,
        TLSConfig: &tls.Config{
            NextProtos: []string{"h2", "http/1.1"}, // 关键：支持多种 ALPN
        },
    }
    
    log.Printf("🚀 Unified server listening on :%s (h2 + http/1.1)", port)
    log.Printf("📡 ALPN: h2 (标准 gRPC), http/1.1 (gRPC-Web)")
    
    if err := httpServer.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}
```

## CDN 配置

### Cloudflare Workers

Cloudflare 会自动处理 gRPC-Web ↔ gRPC 转换：

```javascript
// Cloudflare Worker (可选)
export default {
  async fetch(request, env) {
    // 如果后端支持 h2，Cloudflare 自动转换
    // gRPC-Web (h3) → gRPC (h2)
    
    return fetch("https://origin.example.com", {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });
  }
}
```

### ALPN 协商流程

```
客户端 → CDN (HTTP/3)
  ↓
CDN 检测后端 ALPN
  ↓
├─ 后端支持 h2
│    → CDN 转换 gRPC-Web → gRPC
│    → 使用 HTTP/2 回源
│
└─ 后端仅支持 http/1.1
     → CDN 直接转发 gRPC-Web
     → 使用 HTTP/1.1 回源
```

## 兼容性矩阵

| 客户端传输 | CDN 协商 | 服务端 ALPN | 服务端处理 | 状态 |
|-----------|---------|-------------|-----------|------|
| HTTP/3 gRPC-Web | → h2 | h2 | 标准 gRPC | ✅ 最优 |
| HTTP/3 gRPC-Web | → http/1.1 | http/1.1 | gRPC-Web | ✅ 兼容 |
| HTTP/2 gRPC | - | h2 | 标准 gRPC | ✅ 传统 |
| WebSocket | - | http/1.1 | WebSocket | ✅ 现有 |

## 性能优化

### QUIC 参数调优

```go
quicConfig := &quic.Config{
    InitialStreamReceiveWindow:     6 * 1024 * 1024,  // 6MB
    MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16MB
    InitialConnectionReceiveWindow: 15 * 1024 * 1024, // 15MB
    MaxConnectionReceiveWindow:     25 * 1024 * 1024, // 25MB
    MaxIdleTimeout:                 30 * time.Second,
    KeepAlivePeriod:                10 * time.Second,
    DisablePathMTUDiscovery:        false, // 启用 MTU 发现
    EnableDatagrams:                false, // 不需要 Datagram
}
```

### 0-RTT 支持

```go
// 客户端缓存 0-RTT token
tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(100)

// 启用 0-RTT
quicConfig.Allow0RTT = true
```

### 连接复用

```go
// 复用 HTTP/3 连接
var http3Client = &http.Client{
    Transport: &http3.RoundTripper{
        TLSClientConfig: tlsConfig,
        QuicConfig:      quicConfig,
    },
}
```

## 部署建议

### 1. 仅客户端升级（推荐）

- 客户端使用 HTTP/3 + gRPC-Web
- 服务端保持现有实现（HTTP/2 gRPC 或 HTTP/1.1 WebSocket）
- CDN 自动适配

### 2. 服务端同时升级

- 服务端支持 ALPN 协商（h2 + http/1.1）
- 自动检测 Content-Type
- 统一处理 gRPC 和 gRPC-Web

### 3. 渐进式迁移

1. 部署新客户端（H3 模式可选）
2. 监控 CDN 回源 ALPN 分布
3. 服务端升级支持 gRPC-Web（可选）
4. 逐步启用 H3 作为默认传输

## 测试计划

### 单元测试

```bash
# gRPC-Web 编解码测试
go test -v ./transport/h3grpc/

# 服务端适配器测试
go test -v ./internal/server/
```

### 集成测试

```bash
# 启动测试服务端
./ewp-core-server -port 8443 -cert test.crt -key test.key

# 客户端连接测试
./ewp-core-client -c config.h3.json

# 端到端测试
curl -x socks5://127.0.0.1:1080 https://www.google.com
```

### 性能测试

```bash
# 对比 HTTP/3 vs HTTP/2 vs WebSocket
benchmark.sh --transport h3grpc --connections 100
benchmark.sh --transport grpc --connections 100
benchmark.sh --transport ws --connections 100
```

## 下一步实施

### 阶段 1: 客户端实现（2-3天）

1. ✅ 配置系统设计完成
2. ⏳ 实现 gRPC-Web 编解码器
3. ⏳ 实现 HTTP/3 传输层
4. ⏳ 集成到 main.go

### 阶段 2: 服务端增强（1-2天）

1. ⏳ 实现 gRPC-Web 适配器
2. ⏳ 支持 ALPN 协商
3. ⏳ 集成到现有服务端

### 阶段 3: 测试和优化（1-2天）

1. ⏳ 端到端测试
2. ⏳ 性能调优
3. ⏳ 文档更新

## 参考资料

- [gRPC-Web Protocol](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md)
- [QUIC Go Documentation](https://quic-go.net/docs/)
- [HTTP/3 Explained](https://http3-explained.haxx.se/)
- [Cloudflare gRPC Support](https://developers.cloudflare.com/fundamentals/reference/grpc-support/)
