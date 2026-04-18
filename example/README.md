# 配置文件示例
**Configuration Examples**

本目录包含各种场景的配置文件示例。

---

## 客户端配置

### [config.example.json](./config.example.json)
**完整配置示例** - H3-gRPC + ECH + Vision 流控

特性：
- ✅ HTTP/3 (QUIC) 传输
- ✅ ECH (Encrypted Client Hello)
- ✅ Vision 流控混淆
- ✅ 多 DoH 服务器竞态查询
- ✅ QUIC 参数优化

适用场景：CDN 中转 + 最强混淆

---

### [config.h3.example.json](./config.h3.example.json)
**H3-gRPC 配置示例**

与 config.example.json 类似，展示 H3-gRPC 传输的完整配置。

---

### [config.ws.example.json](./config.ws.example.json)
**WebSocket 配置示例**

特性：
- ✅ WebSocket 传输
- ✅ ECH 支持
- ✅ Vision 流控
- ✅ 自定义 HTTP 头

适用场景：Workers/Cloudflare Pages 部署

---

### [config.trojan.example.json](./config.trojan.example.json)
**Trojan + TUN 模式示例**

特性：
- ✅ Trojan 协议
- ✅ gRPC 传输
- ✅ TUN 模式（全局代理）
- ✅ 路由规则（国内直连）

适用场景：全局透明代理

---

## 服务端配置

### [server.example.json](./server.example.json)
**基础服务端配置**

WebSocket 模式服务端，适合 Workers 部署。

---

### [server.h3.example.json](./server.h3.example.json)
**HTTP/3 服务端配置**

H3-gRPC 模式服务端，需要 QUIC 支持。

---

### [server.h3grpc-cdn.example.json](./server.h3grpc-cdn.example.json)
**CDN 中转服务端配置**

通过 CDN 中转的 H3-gRPC 服务端。

---

### [server.cdn.example.json](./server.cdn.example.json)
**CDN 优化配置**

针对 CDN 中转优化的服务端配置。

---

### [server.trojan.example.json](./server.trojan.example.json)
**Trojan 服务端配置**

Trojan 协议服务端。

---

## 配置说明

### ECH (Encrypted Client Hello)

所有客户端配置都包含 ECH 配置：

```json
"ech": {
  "enabled": true,
  "config_domain": "cloudflare-ech.com",
  "doh_servers": [
    "https://223.5.5.5/dns-query",
    "https://223.6.6.6/dns-query",
    "https://doh.pub/dns-query"
  ],
  "fallback_on_error": true
}
```

**字段说明**：
- `enabled`: 是否启用 ECH
- `config_domain`: ECH 配置域名（查询 HTTPS 记录）
- `doh_servers`: DoH 服务器列表（竞态查询，第一个成功的获胜）
- `fallback_on_error`: ECH 失败时是否回退到普通 TLS

**DoH 服务器**：
- `223.5.5.5` - 阿里云 DNS（主）
- `223.6.6.6` - 阿里云 DNS（备）
- `doh.pub` - DNSPod（腾讯）

这些服务器在中国大陆访问速度快，避免 Google/Cloudflare 被封锁问题。

**向后兼容**：
- 也支持单个服务器：`"doh_server": "223.5.5.5/dns-query"`
- 会自动添加 `https://` 前缀

---

### Vision 流控

```json
"flow": {
  "enabled": true,
  "padding": [900, 500, 900, 256]
}
```

**字段说明**：
- `enabled`: 是否启用 Vision 流控
- `padding`: 填充参数 `[初始填充, 最小填充, 最大填充, 步长]`

**作用**：
- 动态填充消除流量特征
- 防止 DPI (Deep Packet Inspection) 识别
- 提高抗封锁能力

---

### TUN 模式

```json
"inbounds": [
  {
    "type": "tun",
    "tag": "tun-in",
    "interface_name": "ewp-tun",
    "inet4_address": "10.0.85.1/24",
    "mtu": 1380,
    "auto_route": true,
    "stack": "gvisor"
  }
]
```

**字段说明**：
- `interface_name`: TUN 接口名称
- `inet4_address`: TUN 接口 IP 地址
- `mtu`: 最大传输单元
- `auto_route`: 自动配置路由
- `stack`: 网络栈实现（gvisor/system）

**注意**：
- TUN 模式需要管理员权限
- Windows 需要 `wintun.dll`
- 支持全局透明代理

---

### 路由规则

```json
"route": {
  "final": "proxy-out",
  "rules": [
    {
      "domain_suffix": [".cn", ".test"],
      "outbound": "direct"
    },
    {
      "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"],
      "outbound": "direct"
    }
  ]
}
```

**规则类型**：
- `domain_suffix`: 域名后缀匹配
- `ip_cidr`: IP 地址段匹配
- `outbound`: 匹配后使用的出站

**常见规则**：
- 国内域名/IP 直连
- 局域网直连
- 其他流量走代理

---

## 使用方法

### 客户端

```bash
# 使用配置文件启动
./ewp-core-client -config config.example.json

# 或使用环境变量
export EWP_CONFIG=config.example.json
./ewp-core-client
```

### 服务端

```bash
# 使用配置文件启动
./ewp-core-server -config server.example.json
```

---

## 配置验证

启动时会自动验证配置：
- UUID 格式检查
- 必填字段检查
- 参数范围检查
- 冲突检测

如果配置有误，会显示详细错误信息。

---

## 更多示例

查看 `ewp-core/examples/` 目录获取更多场景的配置示例：
- `trojan-h3grpc-cdn/` - Trojan + H3-gRPC + CDN 中转
- `trojan-h3grpc-direct/` - Trojan + H3-gRPC 直连

---

## 相关文档

- [../ewp-core/doc/CONFIG_DESIGN.md](../ewp-core/doc/CONFIG_DESIGN.md) - 配置系统设计
- [../ewp-core/README.md](../ewp-core/README.md) - 项目主文档
- [../README.md](../README.md) - 仓库根目录文档

---

**最后更新**: 2026-04-18
