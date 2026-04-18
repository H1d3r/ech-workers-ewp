# ECH Security Policy / ECH 安全策略

## 核心原则 / Core Principle

**ECH Workers 严格禁止 ECH 到普通 TLS 的自动回退。**

When ECH is enabled, the client will NEVER automatically fall back to plain TLS 1.3 if ECH fails. This is a critical security policy to prevent downgrade attacks.

## 行为说明 / Behavior Description

### 场景 1: ECH 握手成功
- ✅ 连接建立，使用 ECH 加密 SNI
- ✅ 流量正常传输

### 场景 2: ECH 被拒绝，服务器提供 Retry Config
- ⚠️ 服务器返回 `tls.ECHRejectionError` 并包含 `RetryConfigList`
- 🔄 客户端使用新的 ECH 配置**重试一次**
- ✅ 如果重试成功，连接建立
- ❌ 如果重试失败，连接失败（不回退到普通 TLS）

### 场景 3: ECH 被拒绝，服务器不提供 Retry Config
- ⚠️ 服务器返回 `tls.ECHRejectionError` 但 `RetryConfigList` 为空
- ❌ **连接立即失败**，不进行任何重试
- ❌ **绝不回退到普通 TLS**
- 📝 日志记录: "Server rejected ECH without retry config (secure signal)"

### 场景 4: 其他 TLS 错误（非 ECH rejection）
- ❌ 连接失败，返回原始错误
- ❌ **绝不回退到普通 TLS**

## 代码实现 / Implementation

### 关键配置

在 `ewp-core/common/tls/config.go` 中：

```go
func NewSTDECHConfig(...) (*STDECHConfig, error) {
    // ...
    cfg.config.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
        return errors.New("server rejected ECH")
    }
    // ...
}
```

这个回调确保 ECH rejection 被检测为错误。

### ECH Rejection 处理

在所有 transport 实现中（WebSocket, gRPC, H3-gRPC, XHTTP）：

```go
func (t *Transport) handleECHRejection(err error) error {
    var echRejErr *tls.ECHRejectionError
    if !errors.As(err, &echRejErr) {
        return errors.New("not ECH rejection")
    }
    
    // 关键安全检查：没有 retry config = 不重试
    if len(echRejErr.RetryConfigList) == 0 {
        log.Printf("Server rejected ECH without retry config (secure signal)")
        return errors.New("empty retry config")
    }
    
    // 只有在有 retry config 时才更新配置
    return t.echManager.UpdateFromRetry(echRejErr.RetryConfigList)
}
```

### Dial 逻辑

```go
func (t *Transport) Dial() (transport.TunnelConn, error) {
    conn, err := t.dial()
    if err != nil {
        if t.useECH && t.echManager != nil {
            // 只有当 handleECHRejection 返回 nil（成功更新配置）时才重试
            if echErr := t.handleECHRejection(err); echErr == nil {
                log.Printf("ECH rejected, retrying with updated config...")
                conn, err = t.dial()  // 重试仍然使用 ECH
            }
        }
        // 如果重试失败或不满足重试条件，返回错误
        if err != nil {
            return nil, err
        }
    }
    return conn, nil
}
```

**重要**: 重试时调用的 `t.dial()` 仍然使用 `t.useECH = true`，因此重试连接仍然是 ECH 连接。

## 验证方法 / Verification

### 测试场景

1. **正常 ECH 服务器**
   ```bash
   # 应该成功连接
   ./ewp-core-client -config client.json
   ```

2. **ECH 配置错误的服务器**
   ```bash
   # 应该失败，不回退到普通 TLS
   # 日志应显示: "Server rejected ECH without retry config"
   ```

3. **不支持 ECH 的服务器**
   ```bash
   # 应该失败，不回退到普通 TLS
   # 日志应显示 TLS 握手错误
   ```

### 抓包验证

使用 Wireshark 抓包，确认：
- ✅ 成功的连接中，ClientHello 包含 ECH extension
- ❌ 失败的连接中，没有第二个不带 ECH 的 ClientHello（证明没有回退）

## 安全理由 / Security Rationale

### 为什么禁止自动回退？

1. **防止降级攻击**: 攻击者可能主动干扰 ECH 握手，迫使客户端回退到普通 TLS，从而暴露 SNI
2. **明确的安全边界**: 用户启用 ECH 时，期望所有连接都使用 ECH。自动回退违背了这个期望
3. **可审计性**: 禁止回退使得连接行为可预测，便于安全审计
4. **符合最佳实践**: 类似于 HSTS（HTTP Strict Transport Security），一旦启用就不应该降级

### Retry Config 的作用

服务器提供 Retry Config 是一个**合法的 ECH 配置更新机制**：
- 服务器可能轮换 ECH 密钥
- 客户端的 ECH 配置可能过期
- Retry Config 允许客户端获取最新配置并重试

这不是"回退"，而是"配置更新后的重试"，仍然使用 ECH。

## 配置选项 / Configuration

目前**没有配置选项**可以启用 ECH 到普通 TLS 的回退。这是设计决策，不是缺陷。

如果用户需要在 ECH 失败时使用普通 TLS，应该：
1. 配置两个不同的节点（一个启用 ECH，一个不启用）
2. 在应用层实现故障转移逻辑

## 相关代码文件 / Related Files

- `ewp-core/common/tls/config.go` - TLS 配置和 ECH 初始化
- `ewp-core/common/tls/ech.go` - ECH Manager 实现
- `ewp-core/transport/websocket/transport.go` - WebSocket transport ECH 处理
- `ewp-core/transport/grpc/transport.go` - gRPC transport ECH 处理
- `ewp-core/transport/h3grpc/transport.go` - HTTP/3 transport ECH 处理
- `ewp-core/transport/xhttp/transport.go` - XHTTP transport ECH 处理

## 审计日志 / Audit Log

- **2026-04-17**: P1-12 - 统一 ECH 错误检测，使用 `errors.As(*tls.ECHRejectionError)`
- **2026-04-18**: 创建本文档，明确 ECH 安全策略
- **2026-04-18**: 验证所有 transport 实现均符合"不回退"策略

## 结论 / Conclusion

✅ **ECH Workers 当前实现是安全的**

- ECH 失败时**不会**自动回退到普通 TLS
- 只有在服务器提供有效 Retry Config 时才会重试（仍使用 ECH）
- 所有 transport 实现（WebSocket, gRPC, H3-gRPC, XHTTP）均遵循此策略

这符合安全最佳实践，保护用户免受降级攻击。
