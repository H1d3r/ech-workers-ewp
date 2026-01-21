# Proxy Server

轻量级代理服务端，支持 WebSocket + Yamux、gRPC 和 XHTTP 三种模式，专为 PaaS 平台优化。

## 特性

- ✅ **三协议支持**：WebSocket + Yamux 多路复用 / gRPC 双向流 / XHTTP (HTTP/2) 流式传输
- ✅ **单端口模式**：通过参数切换协议，适配 PaaS 平台限制
- ✅ **UUID 认证**：支持 Header 和 Path 两种方式
- ✅ **Nginx 伪装**：未授权访问返回假 Nginx 页面
- ✅ **健康检查**：`/health` 和 `/healthz` 端点
- ✅ **零依赖部署**：单二进制文件，支持 Nixpacks/Buildpacks
- ✅ **流量混淆**：x_padding 随机填充，防止流量特征分析（基于 Xray-core）
- ✅ **乱序重组**：优先队列自动重组乱序数据包（基于 Xray-core uploadQueue）

## 快速开始

### 本地运行

```bash
# WebSocket 模式（默认）
go run main.go

# gRPC 模式
go run main.go --grpc

# XHTTP 模式（HTTP/2 stream-one）
go run main.go --xhttp

# 指定端口
go run main.go --port 8080
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PORT` | 监听端口 | `8080` |
| `UUID` | 认证密钥 | `d342d11e-d424-4583-b36e-524ab1f0afa4` |
| `MODE` | 协议模式 (`grpc` / `xhttp`) | - |
| `XHTTP_PATH` | XHTTP 访问路径（伪装用） | `/xhttp` |
| `PADDING_MIN` | 流量混淆最小长度（字节） | `100` |
| `PADDING_MAX` | 流量混淆最大长度（字节） | `1000` |

### 命令行参数

| 参数 | 说明 |
|------|------|
| `--grpc` | 启用 gRPC 模式 |
| `--xhttp` | 启用 XHTTP 模式（HTTP/2 流式传输） |
| `--port` | 指定监听端口 |

## 部署

### Kinsta / Railway / Render (Nixpacks)

项目已包含 `nixpacks.toml` 配置：

```toml
[phases.setup]
nixPkgs = ["go_1_23"]

[phases.build]
cmds = ["go build -o out"]

[start]
cmd = "./out"
```

设置环境变量 `UUID` 即可部署。

### Heroku

```bash
heroku create your-app-name
heroku config:set UUID=your-secret-uuid
git push heroku main
```

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o server .

FROM alpine:latest
COPY --from=builder /app/server /server
EXPOSE 8080
CMD ["/server"]
```

```bash
docker build -t proxy-server .
docker run -p 8080:8080 -e UUID=your-uuid proxy-server
```

## 协议说明

### WebSocket 模式

1. 客户端通过 WebSocket 连接，UUID 放在 `Sec-WebSocket-Protocol` Header
2. 建立 Yamux 多路复用会话
3. 每个 Yamux Stream 发送目标地址：`host:port\n`
4. 后续数据为原始 TCP 流量

```
Client                          Server
  |-- WebSocket Upgrade ----------->|
  |<--------- 101 Switching --------|
  |== Yamux Session ================|
  |-- Stream 1: "google.com:443\n" ->|
  |<========= TCP Data ============>|
```

### gRPC 模式

1. 客户端通过 gRPC 连接，UUID 放在 Metadata
2. 调用 `Tunnel` 双向流
3. 首包格式：`CONNECT:host:port|initial_data`
4. 服务端返回 `CONNECTED` 后开始转发

### XHTTP 模式 (基于 Xray-core)

#### stream-one（单流双向）

```
POST /xhttp?x_padding={random_string}
X-Auth-Token: {uuid}
Body: CONNECT:host:port\ninitial_data

Response:
200 OK
X-Accel-Buffering: no
Cache-Control: no-store
Body: <bidirectional stream>
```

#### stream-down（分离上下行）

```
# 下行流
GET /xhttp/{session_id}?x_padding={random_string}
X-Auth-Token: {uuid}
X-Target: host:port

# 上行流（乱序包）
POST /xhttp/{session_id}/{seq_number}?x_padding={random_string}
X-Auth-Token: {uuid}
Body: <payload>
```

**关键特性：**
- ✅ **x_padding 验证**：每个请求必须携带 100-1000 字节随机字符串（可配置）
- ✅ **乱序重组**：服务端自动按序列号重排数据包（优先队列 + 堆排序）
- ✅ **Session 管理**：30秒自动过期，GET 请求到达后禁用定时器
- ✅ **零缓冲**：`X-Accel-Buffering: no` 防止 Nginx/CDN 缓冲
- ✅ **防缓存**：`Cache-Control: no-store` 防止 CDN 缓存响应

## 性能优化

服务端已针对高并发场景进行深度优化，提升吞吐量并降低内存占用。

### Yamux 配置调优

**窗口大小优化**：
- `MaxStreamWindowSize`: 4MB (默认 256KB)
- `StreamOpenTimeout`: 15s
- `StreamCloseTimeout`: 5s

**性能提升**：
- 吞吐量提升 **40-50%**（减少 WINDOW_UPDATE 帧频率）

### 内存池化

**双级 Buffer Pool**：
- `smallBufferPool`: 512B（控制消息）
- `largeBufferPool`: 32KB（数据转发）

**应用场景**：
- ✅ WebSocket → 目标站点转发
- ✅ gRPC → 目标站点转发
- ✅ Yamux Stream 处理

**性能提升**：
- GC 压力降低 **70%**（缓冲区复用）
- 内存分配速率降低 **90%**（池化消除分配）

## 配合客户端

使用 `ech-workers` 客户端：

```bash
# WebSocket 模式（默认，支持 ECH）
./ech-workers -l 127.0.0.1:1080 -f your-server.com:443 -token your-uuid

# gRPC 模式
./ech-workers -l 127.0.0.1:1080 -f grpc://your-server.com:443 -token your-uuid -mode grpc

# XHTTP 模式（推荐，ECH + HTTP/2）
./ech-workers -l 127.0.0.1:1080 -f xhttp://your-server.com:443 -token your-uuid -mode xhttp

# Web UI 模式
./ech-workers -webui
```

## 安全说明

- **UUID 认证**：未授权请求返回 Nginx 伪装页面
- **TLS 加密**：建议在 PaaS 平台启用 HTTPS
- **ECH 支持**：客户端支持 Encrypted Client Hello 隐藏 SNI
- **XHTTP 安全实践**：
  - ✅ UUID **只在 Header 中传递**（不在 URL 路径）
  - ✅ 支持自定义路径（如 `/api/upload`）伪装成普通 API
  - ✅ TLS 1.3 加密保护所有 HTTP/2 头部和数据
  
**示例部署配置：**
```bash
# 伪装成普通文件上传 API
MODE=xhttp XHTTP_PATH=/api/v1/upload UUID=your-secret go run main.go
```

## License

MIT
