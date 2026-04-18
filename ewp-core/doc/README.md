# EWP-Core 文档索引
**EWP-Core Documentation Index**

本目录包含 EWP-Core 的所有技术文档。

---

## 架构与设计

### [ARCHITECTURE.md](./ARCHITECTURE.md)
EWP-Core 整体架构设计文档，包括：
- 模块划分
- 数据流向
- 协议栈设计
- 性能优化策略

### [CONFIG_DESIGN.md](./CONFIG_DESIGN.md)
配置系统设计文档，包括：
- 配置文件格式（JSON）
- 配置项说明
- 向后兼容性
- 配置验证

---

## 协议实现

### [H3_IMPLEMENTATION.md](./H3_IMPLEMENTATION.md)
HTTP/3 (QUIC) 传输层实现文档，包括：
- H3-gRPC 协议设计
- QUIC 参数调优
- 流控机制
- 性能优化

---

## 平台集成

### [ANDROID_INTEGRATION.md](./ANDROID_INTEGRATION.md)
Android 平台集成文档，包括：
- Gomobile 绑定
- VPN Service 实现
- Socket 保护机制
- 权限管理

---

## 功能实现与限制

### [TFO_README.md](./TFO_README.md)
TCP Fast Open (TFO) 实现说明，包括：
- 当前实现范围（socket-level）
- 真正 TFO 的要求
- 平台支持情况
- 未来改进计划

**相关 Issue**: P2-38

### [KEEPALIVE_TODO.md](./KEEPALIVE_TODO.md)
HTTP Keep-Alive 实现计划，包括：
- 当前限制说明
- 性能影响分析
- 完整实现计划（5 个阶段）
- 替代方案（SOCKS5/TUN）

**相关 Issue**: P2-10

### [DNS_COMPRESSION_TODO.md](./DNS_COMPRESSION_TODO.md)
DNS 压缩指针鲁棒性改进，包括：
- 当前实现能力
- 已知限制
- RFC 1035 完整合规要求
- 未来改进选项

**相关 Issue**: P2-4

---

## 文档分类

### 设计文档
- ARCHITECTURE.md
- CONFIG_DESIGN.md
- H3_IMPLEMENTATION.md

### 集成文档
- ANDROID_INTEGRATION.md

### 实现说明
- TFO_README.md
- KEEPALIVE_TODO.md
- DNS_COMPRESSION_TODO.md

---

## 相关资源

### 主项目文档
- [../README.md](../README.md) - 项目主文档
- [../../README.md](../../README.md) - 仓库根目录文档

### 配置示例
- [../examples/](../examples/) - 配置文件示例

### 安全审计
- [../../tickets/](../../tickets/) - 安全审计 issue tickets
- [../../REMEDIATION_PROGRESS.md](../../REMEDIATION_PROGRESS.md) - 修复进度总览

---

**最后更新**: 2026-04-18
