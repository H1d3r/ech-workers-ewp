# TCP Fast Open (TFO) Implementation

## Current Status (P2-38)

This implementation provides **socket-level TFO enablement** but does NOT implement true TCP Fast Open with data in SYN packets.

## What This Implementation Does

✅ Sets `TCP_FASTOPEN` socket option on client sockets  
✅ Sets `TCP_FASTOPEN` socket option on server listener sockets  
✅ Allows kernel to use TFO if both sides support it  
✅ Graceful fallback to standard TCP if TFO is not supported  
✅ Cross-platform support (Linux, Windows, macOS, FreeBSD)

## What This Implementation Does NOT Do

❌ Does NOT send application data in the initial SYN packet  
❌ Does NOT reduce connection establishment latency in the first round trip  
❌ Does NOT use `sendto()` with `MSG_FASTOPEN` flag (Linux)  
❌ Does NOT use `ConnectEx()` with data (Windows)  
❌ Does NOT use `connectx()` with data (macOS)

## Technical Details

### Current Approach
```go
// Sets socket option, then uses standard Dial
d := &net.Dialer{
    Control: func(network, address string, c syscall.RawConn) error {
        return c.Control(func(fd uintptr) {
            syscall.SetsockoptInt(fd, IPPROTO_TCP, TCP_FASTOPEN, ...)
        })
    },
}
conn, err := d.DialContext(ctx, "tcp", address)
```

This performs a normal 3-way handshake:
1. Client → Server: SYN (no data)
2. Server → Client: SYN-ACK
3. Client → Server: ACK
4. Client → Server: Data (first write)

### True TFO Approach (Not Implemented)
```go
// Would need to use sendto with MSG_FASTOPEN
fd := socket(AF_INET, SOCK_STREAM, 0)
setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, ...)
sendto(fd, data, MSG_FASTOPEN, addr)  // Sends SYN with data
```

This would perform TFO handshake:
1. Client → Server: SYN + Data (combined)
2. Server → Client: SYN-ACK + Response
3. Client → Server: ACK

## Why Not Full TFO Implementation?

1. **Complexity**: Requires low-level socket programming with platform-specific APIs
2. **Compatibility**: May not work behind certain NAT/firewalls that drop SYN packets with data
3. **Buffering**: Requires buffering first write data before connection establishment
4. **Error Handling**: Complex fallback logic when TFO fails
5. **Breaking Changes**: Would require changes to all transport implementations

## Benefits of Current Implementation

1. **Socket-level enablement**: Kernel may use TFO for subsequent connections to the same server
2. **No breaking changes**: Works with existing connection logic
3. **Graceful degradation**: Falls back to standard TCP if TFO is not supported
4. **Cross-platform**: Works on all supported platforms

## Future Improvements

If true TFO is needed, consider:

### Option 1: Use Existing Library
```go
import "github.com/getlantern/go-tfo"

conn, err := tfo.Dial("tcp", address)
```

### Option 2: Custom Implementation
Implement platform-specific TFO:
- **Linux**: `sendto()` with `MSG_FASTOPEN`
- **Windows**: `ConnectEx()` with initial data
- **macOS**: `connectx()` with `CONNECT_DATA_IDEMPOTENT`

### Option 3: Hybrid Approach
- Try true TFO first
- Fall back to socket-level TFO (current implementation)
- Fall back to standard TCP

## Configuration

Currently, TFO is always attempted when using `DialTFO()` or `ListenTFO()`.

To disable TFO, use standard `net.Dial()` or `net.Listen()` instead.

## Platform Support

| Platform | Socket Option | True TFO | Kernel Version |
|----------|--------------|----------|----------------|
| Linux    | ✅ Yes       | ❌ No    | 3.7+           |
| Windows  | ✅ Yes       | ❌ No    | 10 (1607+)     |
| macOS    | ✅ Yes       | ❌ No    | 10.11+         |
| FreeBSD  | ✅ Yes       | ❌ No    | 12.0+          |

## References

- [RFC 7413: TCP Fast Open](https://tools.ietf.org/html/rfc7413)
- [Linux TFO Documentation](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [go-tfo Library](https://github.com/getlantern/go-tfo)

## Related Issues

- P2-38: TFO Actual Activation / TFO 真正启用
