# EWP-Core 配置系统设计

## 设计目标

1. **模块化**: 参考 sing-box/Xray 的结构化配置
2. **可扩展**: 支持新传输层（H3/gRPC-Web）和协议
3. **向后兼容**: 命令行参数仍可用（映射到配置）
4. **类型安全**: 强类型验证，清晰的错误提示

## 配置结构

### 完整示例

```json
{
  "log": {
    "level": "info",
    "file": "",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1:1080"
    },
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1:1081"
    },
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1:8080"
    },
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "ewp-tun",
      "inet4_address": "10.0.85.1/24",
      "mtu": 1380,
      "auto_route": true,
      "stack": "gvisor"
    }
  ],
  "outbounds": [
    {
      "type": "ewp",
      "tag": "proxy-h3",
      "server": "cdn.example.com",
      "server_port": 443,
      "server_ip": "104.16.0.1",
      "uuid": "your-uuid-here",
      "transport": {
        "type": "h3grpc",
        "service_name": "ProxyService",
        "grpc_web": {
          "mode": "binary",
          "max_message_size": 4194304
        },
        "concurrency": 4
      },
      "tls": {
        "enabled": true,
        "server_name": "cdn.example.com",
        "insecure": false,
        "ech": {
          "enabled": true,
          "config_domain": "cloudflare-ech.com",
          "doh_server": "dns.alidns.com/dns-query"
        },
        "pqc": false,
        "alpn": ["h3"]
      },
      "flow": {
        "enabled": true,
        "padding": [900, 500, 900, 256]
      }
    },
    {
      "type": "ewp",
      "tag": "proxy-ws",
      "server": "worker.example.com",
      "server_port": 443,
      "uuid": "your-uuid-here",
      "transport": {
        "type": "ws",
        "path": "/ws",
        "headers": {
          "User-Agent": "Mozilla/5.0"
        }
      },
      "tls": {
        "enabled": true,
        "ech": {
          "enabled": false
        }
      },
      "flow": {
        "enabled": true
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-grpc",
      "server": "trojan.example.com",
      "server_port": 443,
      "password": "your-password",
      "transport": {
        "type": "grpc",
        "service_name": "TrojanService"
      },
      "multiplex": {
        "enabled": true,
        "concurrency": 8,
        "padding": false
      },
      "tls": {
        "enabled": true
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "final": "proxy-h3",
    "rules": [
      {
        "domain_suffix": [".cn", ".test"],
        "outbound": "direct"
      },
      {
        "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"],
        "outbound": "direct"
      },
      {
        "protocol": ["bittorrent"],
        "outbound": "block"
      }
    ]
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "https://dns.google/dns-query"
      },
      {
        "tag": "local",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "final": "google"
  }
}
```

## 配置字段说明

### Log 日志配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | string | `"info"` | 日志级别: `debug`, `info`, `warn`, `error` |
| `file` | string | `""` | 日志文件路径（空则输出到 stdout） |
| `timestamp` | bool | `true` | 是否显示时间戳 |

### Inbound 入站配置

#### 通用字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | string | ✅ | 入站类型: `mixed`, `socks`, `http`, `tun` |
| `tag` | string | ✅ | 入站标签（唯一标识） |

#### Mixed (SOCKS5 + HTTP)

```json
{
  "type": "mixed",
  "tag": "mixed-in",
  "listen": "127.0.0.1:1080",
  "udp": true
}
```

#### TUN

```json
{
  "type": "tun",
  "tag": "tun-in",
  "interface_name": "ewp-tun",
  "inet4_address": "10.0.85.1/24",
  "inet6_address": "fdfe:dcba:9876::1/126",
  "mtu": 1380,
  "auto_route": true,
  "strict_route": true,
  "stack": "gvisor",
  "platform": {
    "http_proxy": {
      "enabled": true,
      "server": "127.0.0.1",
      "server_port": 8080
    }
  }
}
```

### Outbound 出站配置

#### EWP 协议

```json
{
  "type": "ewp",
  "tag": "proxy",
  "server": "example.com",
  "server_port": 443,
  "server_ip": "1.2.3.4",
  "uuid": "uuid-here",
  "transport": { /* 见传输层配置 */ },
  "tls": { /* 见 TLS 配置 */ },
  "flow": { /* 见 Flow 配置 */ }
}
```

#### Trojan 协议

```json
{
  "type": "trojan",
  "tag": "trojan",
  "server": "example.com",
  "server_port": 443,
  "password": "password-here",
  "transport": { /* 见传输层配置 */ },
  "multiplex": {
    "enabled": true,
    "concurrency": 8,
    "padding": false
  },
  "tls": { /* 见 TLS 配置 */ }
}
```

#### Direct / Block

```json
{
  "type": "direct",
  "tag": "direct"
}
```

### Transport 传输层配置

#### WebSocket

```json
{
  "type": "ws",
  "path": "/ws",
  "headers": {
    "Host": "example.com",
    "User-Agent": "Mozilla/5.0"
  },
  "max_early_data": 2048,
  "early_data_header_name": "Sec-WebSocket-Protocol"
}
```

#### gRPC

```json
{
  "type": "grpc",
  "service_name": "ProxyService",
  "idle_timeout": "15s",
  "health_check_timeout": "10s",
  "permit_without_stream": true,
  "initial_window_size": 4194304
}
```

#### H3 + gRPC-Web（新）

```json
{
  "type": "h3grpc",
  "service_name": "ProxyService",
  "grpc_web": {
    "mode": "binary",
    "max_message_size": 4194304,
    "compression": "none"
  },
  "concurrency": 4,
  "idle_timeout": "30s",
  "quic": {
    "initial_stream_window_size": 6291456,
    "max_stream_window_size": 16777216,
    "initial_connection_window_size": 15728640,
    "max_connection_window_size": 25165824,
    "max_idle_timeout": "30s",
    "keep_alive_period": "10s",
    "disable_path_mtu_discovery": false
  }
}
```

#### XHTTP

```json
{
  "type": "xhttp",
  "path": "/xhttp",
  "mode": "auto",
  "headers": {},
  "concurrency": 2
}
```

### TLS 配置

```json
{
  "enabled": true,
  "server_name": "example.com",
  "insecure": false,
  "alpn": ["h3", "h2", "http/1.1"],
  "ech": {
    "enabled": true,
    "config_domain": "cloudflare-ech.com",
    "doh_server": "dns.alidns.com/dns-query",
    "fallback_on_error": true
  },
  "pqc": false,
  "min_version": "1.2",
  "max_version": "1.3",
  "cipher_suites": [],
  "certificate": "",
  "certificate_path": "",
  "key": "",
  "key_path": ""
}
```

### Flow 配置

```json
{
  "enabled": true,
  "padding": [900, 500, 900, 256]
}
```

### Route 路由配置

```json
{
  "final": "proxy",
  "auto_detect_interface": true,
  "rules": [
    {
      "inbound": ["tun-in"],
      "domain": ["google.com"],
      "domain_suffix": [".cn"],
      "domain_keyword": ["test"],
      "domain_regex": ["^.*\\.example\\.com$"],
      "ip_cidr": ["10.0.0.0/8"],
      "protocol": ["http", "tls", "quic"],
      "source_ip_cidr": ["192.168.1.0/24"],
      "port": [80, 443],
      "port_range": ["1000:2000"],
      "outbound": "direct"
    }
  ]
}
```

## 命令行兼容性映射

| 旧命令行参数 | 新配置路径 | 备注 |
|-------------|-----------|------|
| `-l 127.0.0.1:1080` | `inbounds[0].listen` | 创建 mixed 入站 |
| `-f example.com:443` | `outbounds[0].server` + `server_port` | |
| `-ip 1.2.3.4` | `outbounds[0].server_ip` | |
| `-token uuid` | `outbounds[0].uuid` | |
| `-password pwd` | `outbounds[0].password` | Trojan |
| `-mode ws` | `outbounds[0].transport.type` | |
| `-flow` | `outbounds[0].flow.enabled` | |
| `-pqc` | `outbounds[0].tls.pqc` | |
| `-fallback` | `outbounds[0].tls.ech.enabled = false` | |
| `-ech domain` | `outbounds[0].tls.ech.config_domain` | |
| `-dns doh-server` | `outbounds[0].tls.ech.doh_server` | |
| `-tun` | 创建 `tun` 入站 | |
| `-verbose` | `log.level = "debug"` | |
| `-logfile path` | `log.file` | |

## 配置加载优先级

1. **配置文件** (`-c config.json`)
2. **命令行参数** (覆盖配置文件)
3. **环境变量** (可选)

## 验证规则

### 必需字段验证

- `outbounds` 至少需要一个出站
- `outbounds[].type` 必须是有效值
- `outbounds[].tag` 必须唯一
- `route.final` 必须指向已存在的 outbound

### 类型验证

- `server_port`: 1-65535
- `mtu`: >= 576
- `uuid`: 标准 UUID 格式
- `ip_cidr`: 有效的 CIDR 格式

### 逻辑验证

- TLS enabled + ECH enabled 时，必须提供 `config_domain` 或 `doh_server`
- `type: h3grpc` 时，`tls.alpn` 必须包含 `h3`
- Trojan 协议必须提供 `password`

## 配置文件位置

优先级从高到低：

1. `-c` 参数指定
2. `./config.json`
3. `~/.config/ewp-core/config.json` (Linux/macOS)
4. `%APPDATA%\ewp-core\config.json` (Windows)

## 示例场景

### 场景 1: H3 + CDN 加速

```json
{
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1:1080"}],
  "outbounds": [{
    "type": "ewp",
    "tag": "proxy",
    "server": "cdn.cloudflare.com",
    "server_ip": "104.16.0.1",
    "uuid": "xxx",
    "transport": {
      "type": "h3grpc",
      "service_name": "ProxyService",
      "grpc_web": {"mode": "binary"}
    },
    "tls": {
      "enabled": true,
      "ech": {"enabled": true}
    }
  }]
}
```

### 场景 2: 多协议 Fallback

```json
{
  "outbounds": [
    {"type": "ewp", "tag": "h3", "transport": {"type": "h3grpc"}, "..."},
    {"type": "ewp", "tag": "ws", "transport": {"type": "ws"}, "..."},
    {"type": "trojan", "tag": "trojan", "..."}
  ],
  "route": {
    "final": "h3"
  }
}
```

### 场景 3: TUN 分流

```json
{
  "inbounds": [{"type": "tun", "tag": "tun-in"}],
  "outbounds": [
    {"type": "ewp", "tag": "proxy"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "final": "proxy",
    "rules": [
      {"domain_suffix": [".cn"], "outbound": "direct"},
      {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"}
    ]
  }
}
```

## 迁移指南

### 从命令行迁移

旧方式：
```bash
ewp-core-client -l 127.0.0.1:1080 -f server.com:443 -token uuid -mode ws -flow
```

新方式：
```bash
# 1. 生成配置
ewp-core-client generate -l 127.0.0.1:1080 -f server.com:443 -token uuid > config.json

# 2. 使用配置
ewp-core-client -c config.json
```

或者仍使用命令行（内部转换为配置）：
```bash
ewp-core-client -l 127.0.0.1:1080 -f server.com:443 -token uuid
```

## 未来扩展

- [ ] 支持多配置文件合并
- [ ] 支持配置热重载
- [ ] 支持远程配置订阅
- [ ] 支持配置模板继承
- [ ] 支持环境变量替换 `${ENV_VAR}`
