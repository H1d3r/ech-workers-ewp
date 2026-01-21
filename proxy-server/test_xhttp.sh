#!/bin/bash
# XHTTP 服务端测试脚本

UUID="d342d11e-d424-4583-b36e-524ab1f0afa4"
SERVER="http://localhost:8080"

echo "🧪 测试 XHTTP 服务端"
echo "===================="

# 测试 1: 健康检查
echo -e "\n1️⃣  测试健康检查..."
curl -s http://localhost:8080/health

# 测试 2: 未授权访问（应该返回 Nginx 伪装页面）
echo -e "\n\n2️⃣  测试未授权访问..."
curl -s http://localhost:8080/xhttp | head -n 2

# 测试 3: 错误的路径（应该返回 404）
echo -e "\n\n3️⃣  测试错误路径..."
curl -s -H "X-Auth-Token: $UUID" http://localhost:8080/wrong-path | head -n 2

# 测试 4: 正确的 XHTTP 请求（需要 HTTP/2，这里只测试头部）
echo -e "\n\n4️⃣  测试正确的 XHTTP 请求..."
echo "提示: 完整测试需要 HTTP/2 客户端"
curl -s -X POST \
  -H "X-Auth-Token: $UUID" \
  -H "Content-Type: application/octet-stream" \
  --http2-prior-knowledge \
  --data-binary "CONNECT:example.com:80\n" \
  http://localhost:8080/xhttp | head -c 20

echo -e "\n\n✅ 测试完成"
