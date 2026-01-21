# XHTTP 客户端使用示例

基于 Xray-core 的 XHTTP 协议实现，包含流量混淆和乱序重组功能。

## 1. stream-one 模式（推荐）

### 最简单的双向流实现

```bash
# 生成随机 padding（100-1000 字节）
PADDING=$(openssl rand -base64 750 | tr -d '\n=' | head -c 500)

# 发送请求
curl -X POST "https://server.com/xhttp?x_padding=$PADDING" \
  -H "X-Auth-Token: d342d11e-d424-4583-b36e-524ab1f0afa4" \
  --http2 \
  --data-binary "CONNECT:example.com:443
INITIAL_DATA_HERE" \
  --no-buffer
```

### Python 实现

```python
import requests
import random
import string

def generate_padding(min_len=100, max_len=1000):
    length = random.randint(min_len, max_len)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def stream_one_connect(server_url, target_host, target_port, uuid):
    padding = generate_padding()
    
    headers = {
        'X-Auth-Token': uuid,
        'Content-Type': 'application/octet-stream'
    }
    
    connect_msg = f"CONNECT:{target_host}:{target_port}\n"
    
    response = requests.post(
        f"{server_url}/xhttp",
        params={'x_padding': padding},
        headers=headers,
        data=connect_msg.encode(),
        stream=True
    )
    
    if response.status_code == 200:
        print("✅ Connected!")
        return response
    else:
        print(f"❌ Failed: {response.status_code}")
        return None

# 使用示例
session = stream_one_connect(
    "https://your-server.com",
    "example.com",
    443,
    "d342d11e-d424-4583-b36e-524ab1f0afa4"
)

if session:
    # 发送数据
    session.raw.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    
    # 接收数据
    for chunk in session.iter_content(chunk_size=8192):
        print(chunk.decode('utf-8', errors='ignore'))
```

## 2. stream-down 模式（分离上下行）

### 下行流（GET）

```bash
SESSION_ID=$(uuidgen | tr -d '-')
PADDING=$(openssl rand -base64 750 | tr -d '\n=' | head -c 300)

curl -X GET "https://server.com/xhttp/$SESSION_ID?x_padding=$PADDING" \
  -H "X-Auth-Token: your-uuid" \
  -H "X-Target: example.com:443" \
  --http2 \
  --no-buffer
```

### 上行流（POST with sequence）

```bash
# 发送第 0 个包
curl -X POST "https://server.com/xhttp/$SESSION_ID/0?x_padding=$PADDING" \
  -H "X-Auth-Token: your-uuid" \
  --data-binary @packet0.bin

# 发送第 1 个包
curl -X POST "https://server.com/xhttp/$SESSION_ID/1?x_padding=$PADDING" \
  -H "X-Auth-Token: your-uuid" \
  --data-binary @packet1.bin

# 乱序发送也可以（服务端会自动重组）
curl -X POST "https://server.com/xhttp/$SESSION_ID/3?x_padding=$PADDING" ...
curl -X POST "https://server.com/xhttp/$SESSION_ID/2?x_padding=$PADDING" ...
```

### Python 实现（支持乱序）

```python
import requests
import uuid
import random
import threading
import queue

def stream_down_connect(server_url, target, auth_uuid):
    session_id = uuid.uuid4().hex
    
    # 启动下行流（GET）
    def download_thread():
        padding = generate_padding()
        resp = requests.get(
            f"{server_url}/xhttp/{session_id}",
            params={'x_padding': padding},
            headers={
                'X-Auth-Token': auth_uuid,
                'X-Target': target
            },
            stream=True
        )
        
        for chunk in resp.iter_content(chunk_size=8192):
            print(f"📥 Received: {len(chunk)} bytes")
    
    down_thread = threading.Thread(target=download_thread)
    down_thread.start()
    
    # 上行流发送函数
    def upload_packet(seq, data):
        padding = generate_padding()
        resp = requests.post(
            f"{server_url}/xhttp/{session_id}/{seq}",
            params={'x_padding': padding},
            headers={'X-Auth-Token': auth_uuid},
            data=data
        )
        print(f"📤 Sent seq={seq}: {resp.status_code}")
    
    return upload_packet

# 使用示例
upload = stream_down_connect(
    "https://your-server.com",
    "example.com:443",
    "your-uuid"
)

# 模拟乱序上传
packets = [
    (0, b"GET / HTTP/1.1\r\n"),
    (1, b"Host: example.com\r\n"),
    (2, b"Connection: close\r\n\r\n")
]

# 随机打乱顺序
random.shuffle(packets)

for seq, data in packets:
    upload(seq, data)
```

## 3. 流量混淆策略

### 动态 Padding 长度

```python
import time
import hashlib

def dynamic_padding(base_time=None):
    """基于时间戳生成动态长度的 padding"""
    if base_time is None:
        base_time = int(time.time())
    
    # 使用时间戳的哈希值决定长度
    hash_val = int(hashlib.sha256(str(base_time).encode()).hexdigest()[:8], 16)
    length = 100 + (hash_val % 900)  # 100-1000
    
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
```

### Referer 伪装（浏览器模式）

```python
# 模拟浏览器请求
headers = {
    'X-Auth-Token': uuid,
    'Referer': f'https://www.google.com/search?q={generate_padding()}',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
}

# 服务端会从 Referer 的 query 中提取 padding
```

## 4. 错误处理

### 400 Bad Request - Padding 长度错误

```python
# 错误示例
padding = "abc"  # 太短 (< 100)

# 正确示例
padding = generate_padding(100, 1000)
```

### 404 Not Found - Session 不存在

```python
# 确保先发送 GET 请求创建 session，再发送 POST 上传
```

### 500 Internal Server Error - 队列溢出

```python
# 减少并发上传数量，或增加发送间隔
import time
for seq, data in packets:
    upload(seq, data)
    time.sleep(0.01)  # 10ms 间隔
```

## 5. 性能优化建议

### HTTP/2 多路复用

```python
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

session = requests.Session()
session.mount('https://', HTTPAdapter(
    pool_connections=10,
    pool_maxsize=100,
    max_retries=Retry(total=3)
))
```

### 批量上传

```python
# 使用线程池并发上传
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [
        executor.submit(upload, seq, data)
        for seq, data in packets
    ]
```

## 6. 测试工具

### 简单测试脚本

```bash
#!/bin/bash

SERVER="https://your-server.com"
UUID="d342d11e-d424-4583-b36e-524ab1f0afa4"

# 生成 padding
gen_padding() {
    openssl rand -base64 $((RANDOM % 900 + 100)) | tr -d '\n='
}

# stream-one 测试
test_stream_one() {
    echo "Testing stream-one mode..."
    PADDING=$(gen_padding)
    
    echo -n "CONNECT:httpbin.org:80
GET /ip HTTP/1.1
Host: httpbin.org

" | curl -X POST "$SERVER/xhttp?x_padding=$PADDING" \
        -H "X-Auth-Token: $UUID" \
        --http2 \
        --data-binary @- \
        --no-buffer
}

test_stream_one
```

## 7. 环境变量配置

服务端可通过环境变量调整 padding 验证范围：

```bash
export PADDING_MIN=200    # 最小 200 字节
export PADDING_MAX=2000   # 最大 2000 字节
```

客户端需相应调整生成范围：

```python
padding = generate_padding(200, 2000)
```
