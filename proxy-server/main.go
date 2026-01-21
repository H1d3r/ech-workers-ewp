package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "proxy-server/proto"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var (
	uuid          = getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4")
	port          = getEnv("PORT", "8080")
	xhttpPath     = getEnv("XHTTP_PATH", "/xhttp")
	paddingMin    = getEnvInt("PADDING_MIN", 100)
	paddingMax    = getEnvInt("PADDING_MAX", 1000)
	grpcMode      = false
	xhttpMode     = false
	upgrader      = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

// ======================== Buffer Pool (性能优化) ========================

var (
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 512)
		},
	}

	largeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

// Nginx disguise page
const nginxHTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`

func main() {
	// 解析命令行参数
	flag.BoolVar(&grpcMode, "grpc", false, "启用 gRPC 模式")
	flag.BoolVar(&xhttpMode, "xhttp", false, "启用 XHTTP 模式")
	flag.StringVar(&port, "port", port, "监听端口")
	flag.Parse()

	// 也支持环境变量 MODE=grpc/xhttp
	mode := os.Getenv("MODE")
	if mode == "grpc" {
		grpcMode = true
	} else if mode == "xhttp" {
		xhttpMode = true
	}

	log.Printf("🔑 UUID: %s", uuid)

	if err := initEWPHandler(uuid); err != nil {
		log.Fatalf("❌ Failed to initialize EWP handler: %v", err)
	}

	if grpcMode {
		// gRPC 模式
		log.Printf("🚀 gRPC server listening on :%s", port)
		startGRPCServer()
	} else if xhttpMode {
		// XHTTP 模式
		log.Printf("🚀 XHTTP server listening on :%s", port)
		startXHTTPServer()
	} else {
		// WebSocket 模式（默认）
		mux := http.NewServeMux()
		mux.HandleFunc("/health", healthHandler)
		mux.HandleFunc("/healthz", healthHandler)
		mux.HandleFunc("/", handler)

		server := &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		}

		log.Printf("🚀 WebSocket server listening on :%s", port)
		log.Fatal(server.ListenAndServe())
	}
}

// ======================== gRPC 服务 ========================

type proxyServer struct {
	pb.UnimplementedProxyServiceServer
}

func (s *proxyServer) Tunnel(stream pb.ProxyService_TunnelServer) error {
	log.Println("🔗 gRPC client connected")

	firstMsg, err := stream.Recv()
	if err != nil {
		log.Printf("❌ gRPC: 读取握手失败: %v", err)
		return err
	}

	req, respData, err := handleEWPHandshakeBinary(firstMsg.GetContent())
	if err != nil {
		stream.Send(&pb.SocketData{Content: respData})
		return nil
	}

	if err := stream.Send(&pb.SocketData{Content: respData}); err != nil {
		log.Printf("❌ gRPC: 发送握手响应失败: %v", err)
		return err
	}

	target := req.TargetAddr.String()
	log.Printf("🔗 gRPC connecting to %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ gRPC dial error: %v", err)
		return nil
	}
	defer remote.Close()

	log.Printf("✅ gRPC connected to %s", target)

	// 双向转发
	done := make(chan struct{}, 2)

	// gRPC -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if _, err := remote.Write(msg.GetContent()); err != nil {
				return
			}
		}
	}()

	// remote -> gRPC
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if err := stream.Send(&pb.SocketData{Content: data}); err != nil {
				return
			}
		}
	}()

	<-done
	return nil
}

func parseGRPCConnect(data []byte) (target string, extraData []byte) {
	// 格式: "CONNECT:host:port|extra_data"
	str := string(data)
	if !strings.HasPrefix(str, "CONNECT:") {
		return "", nil
	}

	str = strings.TrimPrefix(str, "CONNECT:")
	idx := strings.Index(str, "|")
	if idx < 0 {
		return str, nil
	}

	target = str[:idx]
	extraData = data[len("CONNECT:")+idx+1:]
	return target, extraData
}

func startGRPCServer() {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("❌ gRPC listen failed: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterProxyServiceServer(s, &proxyServer{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("❌ gRPC serve failed: %v", err)
	}
}

// ======================== XHTTP 服务 (基于 Xray-core 实现) ========================

type xhttpSession struct {
	remote           net.Conn
	uploadQueue      *uploadQueue
	done             chan struct{}
	isFullyConnected chan struct{}
}

var (
	xhttpSessions      = sync.Map{}
	xhttpSessionMutex  sync.Mutex
	xhttpSessionExpiry = 30 * time.Second
)

func startXHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)
	
	mux.HandleFunc(xhttpPath+"/", xhttpHandler)
	mux.HandleFunc(xhttpPath, xhttpHandler)
	mux.HandleFunc("/", disguiseHandler)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go cleanupExpiredSessions()
	log.Fatal(server.ListenAndServe())
}

func xhttpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Token") != uuid {
		disguiseHandler(w, r)
		return
	}

	paddingLen := 0
	if referrer := r.Header.Get("Referer"); referrer != "" {
		if refURL, err := url.Parse(referrer); err == nil {
			paddingLen = len(refURL.Query().Get("x_padding"))
		}
	} else {
		paddingLen = len(r.URL.Query().Get("x_padding"))
	}

	if paddingLen < paddingMin || paddingLen > paddingMax {
		log.Printf("❌ Invalid padding length: %d (expected %d-%d)", paddingLen, paddingMin, paddingMax)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	subpath := strings.TrimPrefix(r.URL.Path, xhttpPath)
	parts := strings.Split(strings.Trim(subpath, "/"), "/")
	
	sessionID := ""
	seqStr := ""
	if len(parts) > 0 && parts[0] != "" {
		sessionID = parts[0]
	}
	if len(parts) > 1 && parts[1] != "" {
		seqStr = parts[1]
	}

	log.Printf("📥 XHTTP %s %s (session=%s, seq=%s, padding=%d)", r.Method, r.URL.Path, sessionID, seqStr, paddingLen)

	if r.Method == "POST" && sessionID != "" {
		xhttpUploadHandler(w, r, sessionID, seqStr)
	} else if r.Method == "GET" && sessionID != "" {
		xhttpDownloadHandler(w, r, sessionID)
	} else if r.Method == "POST" && sessionID == "" {
		xhttpStreamOneHandler(w, r)
	} else if r.Method == "GET" && sessionID == "" {
		xhttpStreamOneHandler(w, r)
	} else {
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func disguiseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(nginxHTML))
}

func upsertSession(sessionID string) *xhttpSession {
	if val, ok := xhttpSessions.Load(sessionID); ok {
		return val.(*xhttpSession)
	}

	xhttpSessionMutex.Lock()
	defer xhttpSessionMutex.Unlock()

	if val, ok := xhttpSessions.Load(sessionID); ok {
		return val.(*xhttpSession)
	}

	session := &xhttpSession{
		uploadQueue:      newUploadQueue(100),
		done:             make(chan struct{}),
		isFullyConnected: make(chan struct{}),
	}
	xhttpSessions.Store(sessionID, session)

	go func() {
		timer := time.NewTimer(xhttpSessionExpiry)
		defer timer.Stop()
		select {
		case <-timer.C:
			if session.remote != nil {
				session.remote.Close()
			}
			close(session.done)
			xhttpSessions.Delete(sessionID)
			log.Printf("🧹 Session expired: %s", sessionID)
		case <-session.isFullyConnected:
		}
	}()

	return session
}

func cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		xhttpSessions.Range(func(key, value interface{}) bool {
			session := value.(*xhttpSession)
			select {
			case <-session.done:
				xhttpSessions.Delete(key)
			default:
			}
			return true
		})
	}
}

func xhttpStreamOneHandler(w http.ResponseWriter, r *http.Request) {
	buf := smallBufferPool.Get().([]byte)
	n, err := r.Body.Read(buf)
	if err != nil && err != io.EOF {
		smallBufferPool.Put(buf)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	target, extraData := parseConnect(buf[:n])
	smallBufferPool.Put(buf)

	if target == "" {
		http.Error(w, "Invalid target", http.StatusBadRequest)
		return
	}

	log.Printf("🔗 stream-one: %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial failed: %v", err)
		http.Error(w, "Connection failed", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()

	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		io.CopyBuffer(remote, r.Body, buf)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				if _, e := w.Write(buf[:n]); e != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	log.Printf("✅ stream-one closed: %s", target)
}

func xhttpDownloadHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	session := upsertSession(sessionID)
	close(session.isFullyConnected)
	defer xhttpSessions.Delete(sessionID)

	if session.remote == nil {
		target := r.Header.Get("X-Target")
		if target == "" {
			http.Error(w, "Missing target", http.StatusBadRequest)
			return
		}

		remote, err := net.Dial("tcp", target)
		if err != nil {
			log.Printf("❌ Dial failed: %v", err)
			http.Error(w, "Connection failed", http.StatusBadGateway)
			return
		}
		session.remote = remote

		go func() {
			buf := largeBufferPool.Get().([]byte)
			defer largeBufferPool.Put(buf)
			for {
				select {
				case <-session.done:
					return
				default:
					n, err := session.uploadQueue.Read(buf)
					if n > 0 {
						if _, e := remote.Write(buf[:n]); e != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
		}()
	}

	log.Printf("📥 stream-down GET: %s", sessionID)

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	buf := largeBufferPool.Get().([]byte)
	defer largeBufferPool.Put(buf)

	for {
		select {
		case <-session.done:
			return
		default:
			n, err := session.remote.Read(buf)
			if n > 0 {
				if _, e := w.Write(buf[:n]); e != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func xhttpUploadHandler(w http.ResponseWriter, r *http.Request, sessionID, seqStr string) {
	val, ok := xhttpSessions.Load(sessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	session := val.(*xhttpSession)

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	buf := largeBufferPool.Get().([]byte)
	defer largeBufferPool.Put(buf)

	if seqStr != "" {
		seq := uint64(0)
		fmt.Sscanf(seqStr, "%d", &seq)
		
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("❌ Upload read error: %v", err)
			return
		}

		if err := session.uploadQueue.Push(Packet{Payload: payload, Seq: seq}); err != nil {
			log.Printf("❌ Upload queue push error: %v", err)
		}
		log.Printf("📤 Packet uploaded: seq=%d, size=%d", seq, len(payload))
	} else {
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				seq := session.uploadQueue.NextSeq()
				if e := session.uploadQueue.Push(Packet{Payload: data, Seq: seq}); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func parseConnect(data []byte) (target string, extraData []byte) {
	str := string(data)
	if !strings.HasPrefix(str, "CONNECT:") {
		return "", nil
	}
	str = strings.TrimPrefix(str, "CONNECT:")
	idx := strings.Index(str, "\n")
	if idx < 0 {
		return strings.TrimSpace(str), nil
	}
	target = str[:idx]
	if idx+1 < len(data) {
		extraData = data[len("CONNECT:")+idx+1:]
	}
	return target, extraData
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generatePadding(minLen, maxLen int) string {
	length := minLen
	if maxLen > minLen {
		diff := maxLen - minLen
		b := make([]byte, 1)
		rand.Read(b)
		length += int(b[0]) % (diff + 1)
	}
	
	padding := make([]byte, length)
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range padding {
		rand.Read(padding[i : i+1])
		padding[i] = chars[padding[i]%byte(len(chars))]
	}
	return string(padding)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("📥 Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Check auth via header or path
	proto := r.Header.Get("Sec-WebSocket-Protocol")
	authorized := proto == uuid || strings.Contains(r.URL.Path, uuid)

	if !authorized || !websocket.IsWebSocketUpgrade(r) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(nginxHTML))
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, http.Header{"Sec-WebSocket-Protocol": {proto}})
	if err != nil {
		log.Printf("❌ Upgrade error: %v", err)
		return
	}
	defer conn.Close()

	log.Println("✅ Client connected")
	handleWebSocket(conn)
}

// WebSocket adapter for yamux
type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			_, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

// handleWebSocket 自动检测客户端协议：Yamux 或 EWP 简单模式
func handleWebSocket(conn *websocket.Conn) {
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("❌ Read first message error: %v", err)
		return
	}

	if len(firstMsg) < 15 {
		log.Printf("❌ Message too short: %d bytes", len(firstMsg))
		return
	}

	// Yamux 协议的 magic: 第一个字节是 0x00（version）
	// EWP 协议：第一个字节是随机 1-255（version）
	if firstMsg[0] == 0x00 {
		log.Println("🔄 Detected Yamux protocol")
		handleYamuxWithFirstFrame(conn, firstMsg)
	} else {
		log.Println("🔄 Detected EWP simple protocol")
		handleSimpleProtocol(conn, firstMsg)
	}
}

// handleSimpleProtocol 处理 EWP 协议（简单 WebSocket 模式）
func handleSimpleProtocol(conn *websocket.Conn, firstMsg []byte) {
	req, respData, err := handleEWPHandshakeBinary(firstMsg)
	if err != nil {
		conn.WriteMessage(websocket.BinaryMessage, respData)
		return
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, respData); err != nil {
		log.Printf("❌ Failed to send handshake response: %v", err)
		return
	}

	target := req.TargetAddr.String()
	log.Printf("🔗 Simple WebSocket connecting to %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial error: %v", err)
		return
	}
	defer remote.Close()

	log.Printf("✅ Simple WebSocket connected to %s", target)

	// 双向转发
	done := make(chan struct{}, 2)

	// WebSocket -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// 检查控制消息
			if str := string(msg); str == "CLOSE" {
				return
			}
			if _, err := remote.Write(msg); err != nil {
				return
			}
		}
	}()

	// remote -> WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				return
			}
		}
	}()

	<-done
	// 发送关闭消息
	conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
}

// handleYamuxWithFirstFrame 处理 Yamux 协议（带已读取的第一帧）
func handleYamuxWithFirstFrame(conn *websocket.Conn, firstFrame []byte) {
	ws := &wsConnWithBuffer{
		Conn:        conn,
		firstFrame:  firstFrame,
		firstFrameRead: false,
	}

	// Create yamux server session（性能优化配置）
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Second

	session, err := yamux.Server(ws, cfg)
	if err != nil {
		log.Printf("❌ Yamux session error: %v", err)
		return
	}
	defer session.Close()

	// Accept streams
	for {
		stream, err := session.Accept()
		if err != nil {
			if err != io.EOF {
				log.Printf("📴 Session closed: %v", err)
			}
			return
		}
		go handleStream(stream)
	}
}

// wsConnWithBuffer 带缓冲的 WebSocket 适配器（用于回放第一帧）
type wsConnWithBuffer struct {
	*websocket.Conn
	firstFrame     []byte
	firstFrameRead bool
	reader         io.Reader
}

func (c *wsConnWithBuffer) Read(p []byte) (int, error) {
	// 先返回已读取的第一帧
	if !c.firstFrameRead && len(c.firstFrame) > 0 {
		c.firstFrameRead = true
		c.reader = bytes.NewReader(c.firstFrame)
	}

	for {
		if c.reader == nil {
			_, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return n, err
	}
}

func (c *wsConnWithBuffer) Write(p []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

func handleYamux(conn *websocket.Conn) {
	ws := &wsConn{Conn: conn}

	// Create yamux server session（性能优化配置）
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Second

	session, err := yamux.Server(ws, cfg)
	if err != nil {
		log.Printf("❌ Yamux session error: %v", err)
		return
	}
	defer session.Close()

	// Accept streams
	for {
		stream, err := session.Accept()
		if err != nil {
			if err != io.EOF {
				log.Printf("📴 Session closed: %v", err)
			}
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	req, respData, err := handleEWPHandshake(stream)
	if err != nil {
		stream.Write(respData)
		return
	}

	if _, err := stream.Write(respData); err != nil {
		log.Printf("❌ Failed to send handshake response: %v", err)
		return
	}

	target := req.TargetAddr.String()
	log.Printf("🔗 Yamux stream connecting to %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial error: %v", err)
		return
	}
	defer remote.Close()

	log.Printf("✅ Yamux stream connected to %s", target)

	// Bidirectional copy
	done := make(chan struct{})
	go func() {
		io.Copy(remote, stream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, remote)
		done <- struct{}{}
	}()
	<-done
}
