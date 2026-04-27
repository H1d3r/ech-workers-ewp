# HTTP Keep-Alive Support (P2-10)

## Current Status

The HTTP proxy currently does NOT support HTTP/1.1 persistent connections (keep-alive).

## Current Behavior

- Each HTTP request creates a new tunnel connection
- Connection is closed after each request/response
- Client must establish new TCP connection for each request
- High latency for multiple requests (RTT accumulation)

## Performance Impact

Without keep-alive:
```
Request 1: TCP handshake (1 RTT) + TLS handshake (2 RTT) + Request (1 RTT) = 4 RTT
Request 2: TCP handshake (1 RTT) + TLS handshake (2 RTT) + Request (1 RTT) = 4 RTT
Total: 8 RTT for 2 requests
```

With keep-alive:
```
Request 1: TCP handshake (1 RTT) + TLS handshake (2 RTT) + Request (1 RTT) = 4 RTT
Request 2: Request (1 RTT) = 1 RTT
Total: 5 RTT for 2 requests (37.5% improvement)
```

## Why Not Implemented Yet

1. **Complex Connection Lifecycle**: Need to manage connection state across multiple requests
2. **Tunnel Reuse**: Current architecture creates one tunnel per request
3. **Header Parsing**: Need to parse `Connection: keep-alive` and `Connection: close` headers
4. **Timeout Management**: Need idle timeout for persistent connections
5. **Error Handling**: Need to handle partial reads/writes across requests
6. **Testing Complexity**: Requires extensive testing for edge cases

## Implementation Plan

### Phase 1: Connection Pool (Foundation)

Create a connection pool for tunnel reuse:

```go
type TunnelPool struct {
    mu      sync.Mutex
    tunnels map[string][]*PooledTunnel // key: target host
    maxIdle int
    maxAge  time.Duration
}

type PooledTunnel struct {
    conn      transport.TunnelConn
    target    string
    createdAt time.Time
    lastUsed  time.Time
}

func (p *TunnelPool) Get(target string) (*PooledTunnel, error)
func (p *TunnelPool) Put(tunnel *PooledTunnel) error
func (p *TunnelPool) Close() error
```

### Phase 2: Request Loop

Modify `HandleConnection` to support multiple requests:

```go
func HandleConnection(conn net.Conn, reader *bufio.Reader, 
    onConnect func(net.Conn, string) error, 
    onProxy func(net.Conn, string, string) error) error {
    
    for {
        req, err := parseRequest(reader)
        if err != nil {
            return err
        }
        
        // Check Connection header
        keepAlive := shouldKeepAlive(req)
        
        // Handle request
        if req.Method == "CONNECT" {
            // CONNECT always closes connection
            return onConnect(conn, req.URL)
        }
        
        // Handle proxy request with tunnel reuse
        if err := handleProxyRequest(conn, req, onProxy); err != nil {
            return err
        }
        
        if !keepAlive {
            return nil
        }
        
        // Continue to next request
    }
}
```

### Phase 3: Tunnel Reuse

Modify tunnel handler to support reuse:

```go
func (h *TunnelHandler) HandleHTTPRequest(
    clientConn net.Conn, 
    target string, 
    request []byte,
    keepAlive bool) error {
    
    // Try to get existing tunnel from pool
    tunnel, err := h.pool.Get(target)
    if err != nil {
        // Create new tunnel
        tunnel, err = h.createTunnel(target)
        if err != nil {
            return err
        }
    }
    
    // Send request
    if err := tunnel.Write(request); err != nil {
        h.pool.Remove(tunnel)
        return err
    }
    
    // Read response
    response, err := readHTTPResponse(tunnel)
    if err != nil {
        h.pool.Remove(tunnel)
        return err
    }
    
    // Send response to client
    if _, err := clientConn.Write(response); err != nil {
        h.pool.Remove(tunnel)
        return err
    }
    
    // Return tunnel to pool if keep-alive
    if keepAlive && isResponseKeepAlive(response) {
        h.pool.Put(tunnel)
    } else {
        tunnel.Close()
    }
    
    return nil
}
```

### Phase 4: Header Management

Implement proper header handling:

```go
func shouldKeepAlive(req *Request) bool {
    // HTTP/1.1 defaults to keep-alive
    if req.Version == "HTTP/1.1" {
        conn := req.Headers["connection"]
        return !strings.EqualFold(conn, "close")
    }
    
    // HTTP/1.0 requires explicit keep-alive
    if req.Version == "HTTP/1.0" {
        conn := req.Headers["connection"]
        return strings.EqualFold(conn, "keep-alive")
    }
    
    return false
}

func addKeepAliveHeaders(headers *strings.Builder, keepAlive bool) {
    if keepAlive {
        headers.WriteString("Connection: keep-alive\r\n")
        headers.WriteString("Keep-Alive: timeout=30, max=100\r\n")
    } else {
        headers.WriteString("Connection: close\r\n")
    }
}
```

### Phase 5: Timeout Management

Implement idle timeout for persistent connections:

```go
const (
    idleTimeout    = 30 * time.Second
    maxRequests    = 100
    tunnelMaxAge   = 5 * time.Minute
)

func (h *TunnelHandler) monitorIdleConnections() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        h.pool.CloseIdleConnections(idleTimeout)
        h.pool.CloseOldConnections(tunnelMaxAge)
    }
}
```

## Testing Requirements

1. **Unit Tests**:
   - Connection pool get/put/remove
   - Header parsing (Connection, Keep-Alive)
   - Timeout handling

2. **Integration Tests**:
   - Multiple requests on same connection
   - Connection reuse across requests
   - Idle timeout
   - Max requests per connection
   - Error recovery

3. **Performance Tests**:
   - Benchmark with/without keep-alive
   - Latency comparison
   - Throughput comparison
   - Memory usage

4. **Compatibility Tests**:
   - curl with keep-alive
   - Browser multiple requests
   - HTTP/1.0 vs HTTP/1.1
   - Connection: close handling

## Risks and Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Connection leaks | High | Implement strict timeout and max age |
| Memory exhaustion | High | Limit pool size and idle connections |
| Stale connections | Medium | Health check before reuse |
| Partial reads | Medium | Proper buffering and error handling |
| Breaking changes | Low | Feature flag for gradual rollout |

## Workarounds (Current)

Users experiencing performance issues can:

1. **Use SOCKS5 instead of HTTP**: SOCKS5 has better connection reuse
2. **Use TUN mode**: Kernel handles connection pooling
3. **Reduce request frequency**: Batch operations when possible
4. **Use HTTP/2**: If server supports it (requires different implementation)

## References

- [RFC 7230 Section 6.3: Persistence](https://tools.ietf.org/html/rfc7230#section-6.3)
- [RFC 2616 Section 8.1: Persistent Connections](https://tools.ietf.org/html/rfc2616#section-8.1)
- [MDN: Connection management in HTTP/1.x](https://developer.mozilla.org/en-US/docs/Web/HTTP/Connection_management_in_HTTP_1.x)

## Related Issues

- P2-10: HTTP Keep-Alive Support / HTTP 代理支持 keep-alive
- P0-5: HTTP Body Truncation (same file, already fixed)
- P2-9: HTTP ABNF Parsing (same file, already fixed)

## Decision

**Status**: Deferred to future release

**Reason**: 
- Complex implementation requiring significant refactoring
- Medium risk of introducing bugs
- Workarounds available (SOCKS5, TUN mode)
- Performance impact is acceptable for current use cases

**Future Work**:
- Implement in v2.0 with full HTTP/1.1 compliance
- Consider HTTP/2 support at the same time
- Add feature flag for gradual rollout
