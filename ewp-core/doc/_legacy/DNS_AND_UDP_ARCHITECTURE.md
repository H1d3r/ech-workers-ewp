# DNS 模块与 UDP NAT 架构详解
**DNS Module and UDP NAT Architecture**

---

## 📚 DNS 模块功能概览

EWP-Core 的 DNS 模块提供了完整的 DNS 解析和管理功能，支持多种使用场景。

### 核心文件功能

```
ewp-core/dns/
├── doh.go              # DoH (DNS over HTTPS) 客户端
├── fakeip.go           # FakeIP 池管理 (TUN 模式)
├── query.go            # DNS 查询构建
├── response.go         # DNS 响应解析 (ECH 配置提取)
├── reverse_mapping.go  # IP→域名反向映射缓存
├── router.go           # DNS 路由器 (统一接口)
└── tunnel_resolver.go  # 通过隧道的 DNS 解析器
```

---

## 1. DoH 客户端 (`doh.go`)

### 功能
DNS over HTTPS 客户端，用于安全的 DNS 查询。

### 使用场景

#### A. ECH 配置查询
```go
// 查询 HTTPS 记录获取 ECH 配置
client := dns.NewClient("https://1.1.1.1/dns-query")
echConfig, err := client.QueryHTTPS("cloudflare-ech.com")
```

**用途**: 
- 启动时获取 ECH (Encrypted Client Hello) 配置
- 定期刷新 ECH 配置 (每小时)
- 支持多服务器竞速 (P0-12)

#### B. 多服务器竞速 (P0-12)
```go
// 同时查询多个 DoH 服务器，第一个成功的获胜
multiClient := dns.NewMultiClient([]string{
    "https://1.1.1.1/dns-query",      // Cloudflare
    "https://8.8.8.8/dns-query",      // Google
    "https://9.9.9.9/dns-query",      // Quad9
}, bypassDialer)

echConfig, err := multiClient.QueryHTTPS("cloudflare-ech.com")
```

**优势**:
- 冗余: 单个服务器故障不影响启动
- 速度: 选择最快响应的服务器
- 抗审查: 某个服务器被封锁时自动切换

---

## 2. FakeIP 池 (`fakeip.go`)

### 功能
为域名分配假 IP，消除 DNS 查询延迟。

### 工作原理

```
客户端查询 google.com
    ↓
FakeIP 池分配 198.18.0.1
    ↓
立即返回假 IP (无需等待真实 DNS)
    ↓
客户端连接 198.18.0.1
    ↓
TUN 拦截，反向查找 → google.com
    ↓
代理服务器解析真实 IP 并连接
```

### IP 范围

```go
// IPv4: 198.18.0.0/15 (131,070 个地址)
// 范围: 198.18.0.1 - 198.19.255.254

// IPv6: fc00::/96 (4,294,967,295 个地址)
// P1-30: 从 /112 (65k) 扩展到 /96 (4B) 防止耗尽
// 范围: fc00::1 - fc00::ffff:ffff
```

### 双向映射

```go
type FakeIPPool struct {
    // 域名 → FakeIP
    domainToIP4 map[string]netip.Addr  // "google.com" → 198.18.0.1
    domainToIP6 map[string]netip.Addr  // "google.com" → fc00::1
    
    // FakeIP → 域名 (反向查找)
    ip4ToDomain map[netip.Addr]string  // 198.18.0.1 → "google.com"
    ip6ToDomain map[netip.Addr]string  // fc00::1 → "google.com"
}
```

### 使用场景

**TUN 模式**:
```go
// 1. 客户端查询 DNS
query := BuildQuery("google.com", TypeA)

// 2. FakeIP 池分配假 IP
fakeIP := pool.AllocateIPv4("google.com")  // 198.18.0.1

// 3. 构建 DNS 响应
response := BuildDNSResponse(query, fakeIP, netip.Addr{})

// 4. 客户端连接假 IP
// TUN 拦截 198.18.0.1:443

// 5. 反向查找真实域名
domain, ok := pool.LookupByIP(fakeIP)  // "google.com"

// 6. 代理服务器解析并连接真实 IP
```

**优势**:
- 零延迟: 无需等待 DNS 查询
- 隐私: DNS 查询不泄露到本地网络
- 统一: 所有 DNS 流量通过隧道

---

## 3. 反向映射 (`reverse_mapping.go`)

### 功能
缓存 IP→域名映射，用于 SOCKS5 模式。

### 工作原理

```
客户端查询 google.com
    ↓
通过隧道查询 DoH
    ↓
返回真实 IP: 142.250.185.46
    ↓
存储反向映射: 142.250.185.46 → google.com
    ↓
客户端连接 142.250.185.46
    ↓
SOCKS5 查找反向映射 → google.com
    ↓
代理服务器使用域名连接 (支持 CDN)
```

### 数据结构 (P2-5: 双向链表 LRU)

```go
type ReverseMapping struct {
    // IP → 域名映射
    mapping map[netip.Addr]*mappingEntry
    
    // LRU 双向链表 (O(1) 插入/删除)
    head *mappingEntry  // 最新
    tail *mappingEntry  // 最旧
    
    // 容量限制
    maxEntries int  // 默认 10,000
}

type mappingEntry struct {
    ip        netip.Addr
    domain    string
    expiresAt time.Time
    
    // 双向链表指针
    prev *mappingEntry
    next *mappingEntry
}
```

### 为什么需要反向映射？

**问题**: CDN 需要域名而不是 IP
```
客户端: 连接 142.250.185.46 (Google CDN IP)
代理服务器: 用 IP 连接 → CDN 不知道服务哪个域名 → 失败

客户端: 连接 142.250.185.46
反向映射: 142.250.185.46 → google.com
代理服务器: 用域名连接 → CDN 正确路由 → 成功
```

---

## 4. 隧道 DNS 解析器 (`tunnel_resolver.go`)

### 功能
通过代理隧道查询 DoH，所有 DNS 流量加密。

### 架构 (P1-4: 连接池)

```
┌─────────────────────────────────────────┐
│     TunnelDNSResolver                   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Connection Pool (8 connections) │   │
│  │                                   │   │
│  │  [Conn 1] ──┐                    │   │
│  │  [Conn 2] ──┤                    │   │
│  │  [Conn 3] ──┤  Round-Robin       │   │
│  │  [Conn 4] ──┤  Dispatch          │   │
│  │  [Conn 5] ──┤                    │   │
│  │  [Conn 6] ──┤                    │   │
│  │  [Conn 7] ──┤                    │   │
│  │  [Conn 8] ──┘                    │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Response Cache (30 min TTL)    │   │
│  │  Max 10,000 entries (P1-5)      │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Inflight Deduplication         │   │
│  │  (Singleflight pattern)         │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### 连接流程

```
客户端 DNS 查询
    ↓
1. 检查缓存 (命中 → 立即返回)
    ↓
2. 检查 inflight (相同查询 → 等待共享结果)
    ↓
3. Round-robin 选择连接池中的一个连接
    ↓
4. 通过隧道建立 TLS 连接到 DoH 服务器
    ↓
5. HTTP/1.1 POST 请求 (串行化)
    ↓
6. 接收响应
    ↓
7. TXID 验证 (P1-16)
    ↓
8. 存入缓存 (30 分钟)
    ↓
9. 返回结果
```

### 为什么需要连接池？

**问题**: HTTP/1.1 每个连接只能串行处理一个请求
```
单连接:
Request 1 ──────────────────────> (5s)
                                  Request 2 ──────────────────────> (5s)
Total: 10s for 2 requests

8 连接池:
Request 1 ──────────────────────> (5s)
Request 2 ──────────────────────> (5s)
Request 3 ──────────────────────> (5s)
...
Total: 5s for 8 requests (并发)
```

---

## 5. DNS 路由器 (`router.go`)

### 功能
统一的 DNS 解析接口，根据模式选择不同的解析策略。

### 模式选择

```go
type DNSRouter interface {
    Exchange(ctx context.Context, query []byte) ([]byte, error)
    LookupReverseMapping(ip netip.Addr) (string, bool)
    IsFakeIP(ip netip.Addr) bool
}
```

#### 模式 1: TUN + FakeIP
```go
router := NewDNSRouter(DNSRouterConfig{
    FakeIPPool: fakeIPPool,
})

// 所有查询返回 FakeIP
response, _ := router.Exchange(ctx, query)
// 返回 198.18.0.1 (立即)
```

#### 模式 2: SOCKS5 + 真实 DNS
```go
router := NewDNSRouter(DNSRouterConfig{
    TunnelResolver: tunnelResolver,
    ReverseMapping: reverseMapping,
})

// 通过隧道查询真实 DNS
response, _ := router.Exchange(ctx, query)
// 返回 142.250.185.46 (通过隧道)
// 同时存储反向映射
```

---

## 🔌 UDP NAT 类型语义

### NAT 类型概述

EWP-Core 实现了 **Full Cone NAT** 语义，支持 NAT 类型检测工具。

### UDP Session Key

```go
type udpSessionKey struct {
    src netip.AddrPort  // 客户端地址:端口
    dst netip.AddrPort  // 目标地址:端口
}
```

**关键设计**: 使用 `(src, dst)` 而不是仅 `src`

### 为什么需要 (src, dst) 作为 Key？

#### 场景: NAT 类型检测工具

NAT 类型检测工具 (如 STUN) 的工作方式:
```
客户端 (192.168.1.100:5000) 发送到:
  - Server A (1.1.1.1:3478)
  - Server B (2.2.2.2:3478)
  - Server C (3.3.3.3:3478)

期望:
  - 从 Server A 收到响应 (源地址 1.1.1.1:3478)
  - 从 Server B 收到响应 (源地址 2.2.2.2:3478)
  - 从 Server C 收到响应 (源地址 3.3.3.3:3478)
```

#### 错误实现 (仅用 src 作为 Key)

```go
// ❌ 错误: 仅用 src
key := src  // 192.168.1.100:5000

// 问题: 所有目标共享同一个 session
session1 := sessions[192.168.1.100:5000]  // → Server A
session2 := sessions[192.168.1.100:5000]  // → 还是 Server A!
session3 := sessions[192.168.1.100:5000]  // → 还是 Server A!

// 结果: 所有响应都来自 Server A
// NAT 检测工具误判为 Symmetric NAT
```

#### 正确实现 (使用 (src, dst) 作为 Key)

```go
// ✅ 正确: 使用 (src, dst)
key1 := (192.168.1.100:5000, 1.1.1.1:3478)
key2 := (192.168.1.100:5000, 2.2.2.2:3478)
key3 := (192.168.1.100:5000, 3.3.3.3:3478)

// 每个目标有独立的 session
session1 := sessions[key1]  // → Server A
session2 := sessions[key2]  // → Server B
session3 := sessions[key3]  // → Server C

// 结果: 每个服务器的响应正确返回
// NAT 检测工具正确识别为 Full Cone NAT
```

### Full Cone NAT 语义

```
Full Cone NAT (完全锥形 NAT):
  - 客户端 192.168.1.100:5000 → 映射到公网 203.0.113.1:12345
  - 任何外部主机都可以发送到 203.0.113.1:12345
  - 数据包会被转发到 192.168.1.100:5000

实现:
  - 每个 (src, dst) 对有独立的隧道连接
  - 每个隧道维护自己的 fakeAddr (响应源地址)
  - 响应直接写回 gVisor 连接 (避免端口冲突)
```

### UDP Session 生命周期

```go
// 1. 客户端发送 UDP 包
HandleUDP(payload, src, dst, conn)

// 2. 创建 session key
key := udpSessionKey{src: src, dst: dst}

// 3. 查找或创建 session
session, ok := udpSessions.Load(key)
if !ok {
    // 创建新 session
    tunnelConn := transport.Dial()
    tunnelConn.ConnectUDP(endpoint, nil)
    
    session = &udpSession{
        tunnelConn: tunnelConn,
        gvisorConn: conn,  // gVisor 为这个流创建的连接
        remoteAddr: dst,
        fakeAddr:   dst,
    }
    
    udpSessions.Store(key, session)
    
    // 启动读循环
    go udpReadLoop(src, key, session)
}

// 4. 发送数据
session.tunnelConn.WriteUDP(endpoint, payload)

// 5. 读循环接收响应
for {
    n, _, err := session.tunnelConn.ReadUDPFrom(buf)
    
    // 直接写回 gVisor 连接
    session.gvisorConn.Write(buf[:n])
}

// 6. 超时清理 (5 分钟无活动)
cleanupUDPSessions()
```

### 为什么直接写回 gVisor 连接？

#### 问题: 端口冲突

```
客户端: 192.168.1.100:5000 → 1.1.1.1:3478

尝试 DialUDP:
  - gVisor 已经绑定了 192.168.1.100:5000
  - 再次 DialUDP 192.168.1.100:5000 → 端口冲突!
```

#### 解决方案: 直接写回

```
gVisor 创建连接时:
  conn := gVisor.CreateUDPConn(src, dst)
  
保存这个连接:
  session.gvisorConn = conn
  
接收响应时:
  session.gvisorConn.Write(response)
  
gVisor 自动:
  - 设置正确的源地址 (dst)
  - 发送到正确的客户端 socket (src)
```

---

## 📊 使用场景对比

| 场景 | DNS 解析 | 反向映射 | FakeIP | 隧道 DNS |
|------|---------|---------|--------|---------|
| TUN 模式 | FakeIP 池 | ❌ | ✅ | ❌ |
| SOCKS5 模式 | 隧道 DNS | ✅ | ❌ | ✅ |
| ECH 启动 | DoH 多服务器 | ❌ | ❌ | ❌ |
| NAT 检测 | FakeIP 池 | ❌ | ✅ | ❌ |

---

## 🔧 配置示例

### TUN 模式 (FakeIP)
```go
fakeIPPool := dns.NewFakeIPPool()
router := dns.NewDNSRouter(dns.DNSRouterConfig{
    FakeIPPool: fakeIPPool,
})

// DNS 查询返回 FakeIP
response, _ := router.Exchange(ctx, query)
```

### SOCKS5 模式 (真实 DNS)
```go
tunnelResolver, _ := dns.NewTunnelDNSResolver(transport, dns.TunnelDNSConfig{
    DoHServer: "https://1.1.1.1/dns-query",
    PoolSize:  8,
    CacheTTL:  30 * time.Minute,
})

reverseMapping := dns.NewReverseMapping(10000)

router := dns.NewDNSRouter(dns.DNSRouterConfig{
    TunnelResolver: tunnelResolver,
    ReverseMapping: reverseMapping,
})

// DNS 查询通过隧道
response, _ := router.Exchange(ctx, query)
```

---

## 🎯 关键优化

1. **P0-12**: DoH 多服务器竞速 (冗余 + 速度)
2. **P1-4**: 隧道 DNS 连接池 (并发查询)
3. **P1-5**: DNS 响应缓存 (30 分钟 TTL, 10k 上限)
4. **P1-16**: TXID 验证 (防止响应混淆)
5. **P1-30**: IPv6 FakeIP 池扩展到 /96 (4B 地址)
6. **P2-3**: 随机 TXID (防止 DPI 指纹识别)
7. **P2-5**: 反向映射双向链表 LRU (O(1) 操作)

---

## 📝 总结

### DNS 模块职责

1. **ECH 配置获取**: DoH 查询 HTTPS 记录
2. **FakeIP 管理**: 零延迟 DNS (TUN 模式)
3. **真实 DNS 解析**: 通过隧道的 DoH (SOCKS5 模式)
4. **反向映射**: IP→域名缓存 (CDN 支持)
5. **DNS 路由**: 统一接口，模式切换

### UDP NAT 语义

1. **Full Cone NAT**: 支持 NAT 类型检测
2. **(src, dst) Session Key**: 每个目标独立 session
3. **直接写回 gVisor**: 避免端口冲突
4. **超时清理**: 5 分钟无活动自动清理

---

**文档版本**: 1.0  
**最后更新**: 2026-04-18
