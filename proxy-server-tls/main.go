package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

var (
	port        = getEnv("PORT", "443")
	backendURL  = getEnv("BACKEND", "http://127.0.0.1:8080")
	certFile    = getEnv("CERT_FILE", "")
	keyFile     = getEnv("KEY_FILE", "")
	selfSigned  = false
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
const nginxHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`

// ======================== 自签名证书生成 ========================

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HTTPS Reverse Proxy"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	// 解析命令行参数
	flag.StringVar(&port, "port", port, "HTTPS 监听端口")
	flag.StringVar(&backendURL, "backend", backendURL, "后端服务器地址 (如 http://127.0.0.1:8080)")
	flag.StringVar(&certFile, "cert", certFile, "TLS 证书文件路径")
	flag.StringVar(&keyFile, "key", keyFile, "TLS 私钥文件路径")
	flag.BoolVar(&selfSigned, "self-signed", selfSigned, "使用自签名证书（用于开发测试）")
	flag.Parse()

	// 解析后端 URL
	backend, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("❌ 无效的后端地址: %v", err)
	}

	// 创建支持 HTTP/2 的 Transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	
	// 显式启用 HTTP/2
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("⚠️ HTTP/2 配置失败，将回退到 HTTP/1.1: %v", err)
	}

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.Transport = transport
	
	// 自定义 Director 以保留原始 Host
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = backend.Host
	}

	// 错误处理
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("❌ 代理错误: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("502 Bad Gateway"))
	}

	// HTTP 处理器
	mux := http.NewServeMux()
	
	// 健康检查
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// 反向代理所有其他请求
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 记录请求
		log.Printf("📥 %s %s %s -> %s", r.RemoteAddr, r.Method, r.URL.Path, backendURL)
		proxy.ServeHTTP(w, r)
	})

	// 配置 TLS
	var tlsConfig *tls.Config

	if selfSigned || (certFile == "" && keyFile == "") {
		// 使用自签名证书
		log.Println("⚠️ 使用自签名证书（仅用于开发测试）")
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("❌ 生成自签名证书失败: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	} else {
		// 使用指定的证书文件
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("❌ 加载证书失败: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
		log.Printf("🔐 使用证书: %s", certFile)
	}

	// 启动 HTTPS 服务器
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("🚀 HTTPS 反向代理已启动 (支持 HTTP/2)")
	log.Printf("   监听: https://0.0.0.0:%s", port)
	log.Printf("   后端: %s", backendURL)

	// 使用空字符串因为证书已在 TLSConfig 中配置
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("❌ 服务器启动失败: %v", err)
	}
}

// disguiseHandler 返回伪装的 nginx 页面
func disguiseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, nginxHTML)
}
