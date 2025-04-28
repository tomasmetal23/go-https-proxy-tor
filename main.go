package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	listenPort   string
	torSOCKSAddr string
	tlsCertFile  string
	tlsKeyFile   string
	caddyAddr    string // Dirección del backend Caddy
)

func init() {
	listenPort = getEnv("LISTEN_PORT", "8443")
	torSOCKSAddr = net.JoinHostPort(getEnv("TOR_SOCKS_HOST", "127.0.0.1"), getEnv("TOR_SOCKS_PORT", "9050"))
	tlsCertFile = getEnv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	tlsKeyFile = getEnv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	caddyAddr = getEnv("CADDY_BACKEND_ADDR", "http://localhost:80")
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// --- Proxy Handler ---

type DualPurposeHandler struct {
	TorSocksAddr string
	CaddyProxy   *httputil.ReverseProxy
	// CaddyBackendURLString string // Alternativa más limpia para logging
}

func NewDualPurposeHandler(torAddr string, caddyBackendURL *url.URL) *DualPurposeHandler {
	caddyProxy := httputil.NewSingleHostReverseProxy(caddyBackendURL)

	originalDirector := caddyProxy.Director
	caddyProxy.Director = func(req *http.Request) {
		originalDirector(req)
		clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			clientIP = req.RemoteAddr
		}
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Forwarded-Proto", "https")
		if req.Host != "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
		// req.Host = req.Header.Get("X-Forwarded-Host") // Descomentar si Caddy lo necesita
	}

	caddyProxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		fmt.Fprintf(os.Stderr, "[%s] Reverse Proxy Error hacia Caddy (%s): %v\n", req.RemoteAddr, caddyBackendURL.Host, err)
		select {
		case <-req.Context().Done():
			fmt.Fprintf(os.Stderr, "[%s] Client disconnected during reverse proxy error handling.\n", req.RemoteAddr)
			return
		default:
			// Evitar pánico "WriteHeader after headers written"
			headerMap := rw.Header()
			if _, written := headerMap["Content-Type"]; !written && headerMap.Get("Content-Length") == "" { // Intenta detectar si ya se escribió
				rw.WriteHeader(http.StatusBadGateway)
			} else {
				fmt.Fprintf(os.Stderr, "[%s] Headers potentially already written, cannot send 502 for reverse proxy error.\n", req.RemoteAddr)
			}
		}
	}

	return &DualPurposeHandler{
		TorSocksAddr: torAddr,
		CaddyProxy:   caddyProxy,
		// CaddyBackendURLString: caddyBackendURL.String(), // Si se usa la alternativa
	}
}

func (h *DualPurposeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logPrefix := fmt.Sprintf("[%s %s %s %s]", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
	fmt.Printf("%s Recibida solicitud\n", logPrefix)

	if r.Method == http.MethodConnect {
		h.handleTunnel(w, r, logPrefix)
	} else {
		// fmt.Printf("%s Reenviando solicitud a Caddy (%s)\n", logPrefix, h.CaddyBackendURLString) // Si se usa la alternativa
		fmt.Printf("%s Reenviando solicitud a Caddy (%s)\n", logPrefix, caddyAddr) // Usando variable global
		h.CaddyProxy.ServeHTTP(w, r)
	}
}

func (h *DualPurposeHandler) handleTunnel(w http.ResponseWriter, r *http.Request, logPrefix string) {
	targetAddr := r.URL.Host
	fmt.Printf("%s Solicitud CONNECT para: %s\n", logPrefix, targetAddr)

	if !strings.Contains(targetAddr, ":") {
		errMsg := "CONNECT target must include port"
		http.Error(w, errMsg, http.StatusBadRequest)
		fmt.Fprintf(os.Stderr, "%s Error: %s (%s)\n", logPrefix, errMsg, targetAddr)
		return
	}

	fmt.Printf("%s Intentando conectar a '%s' via SOCKS5 (%s)\n", logPrefix, targetAddr, h.TorSocksAddr)
	dialer, err := proxy.SOCKS5("tcp", h.TorSocksAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error creando el dialer SOCKS5: %v\n", logPrefix, err)
		http.Error(w, "Internal Server Error (SOCKS dialer)", http.StatusInternalServerError)
		return
	}

	dialContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s Error: El dialer SOCKS5 no soporta DialContext\n", logPrefix)
		http.Error(w, "Internal Server Error (SOCKS dialer context)", http.StatusInternalServerError)
		return
	}

	torConn, err := contextDialer.DialContext(dialContext, "tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error al conectar a '%s' via SOCKS5 (%s): %v\n", logPrefix, targetAddr, h.TorSocksAddr, err)
		errMsg := fmt.Sprintf("Bad Gateway: SOCKS connection to '%s' failed", targetAddr)
		statusCode := http.StatusBadGateway // 502 por defecto
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			errMsg = fmt.Sprintf("Gateway Timeout: SOCKS connection to '%s' timed out", targetAddr)
			statusCode = http.StatusGatewayTimeout // 504 si fue timeout
		}
		http.Error(w, errMsg, statusCode)
		return
	}
	defer torConn.Close()
	fmt.Printf("%s Conexión SOCKS5 establecida a '%s'\n", logPrefix, targetAddr)

	// --- Ahora intentamos el Hijack ---
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// ESTE ES EL ERROR QUE ESTABAS VIENDO
		fmt.Fprintf(os.Stderr, "%s Error CRÍTICO: El ResponseWriter NO soporta Hijacking. Probablemente debido a HTTP/2.\n", logPrefix)
		// Ya no podemos enviar un http.Error porque podríamos haber perdido control.
		// Cerramos la conexión a Tor que ya habíamos establecido.
		torConn.Close()
		// Intentamos cerrar la conexión del cliente abruptamente si es posible (puede fallar)
		if conn, _, HijackErr := w.(http.Hijacker).Hijack(); HijackErr == nil {
			conn.Close()
		}
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error al hacer Hijack de la conexión: %v\n", logPrefix, err)
		torConn.Close()
		return
	}
	defer clientConn.Close()
	fmt.Printf("%s Hijack exitoso. Enviando 200 OK al cliente.\n", logPrefix) // Log añadido

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error al enviar '200 Connection established': %v\n", logPrefix, err)
		return
	}

	fmt.Printf("%s Respuesta '200 OK' enviada. Iniciando túnel bidireccional.\n", logPrefix)

	var wg sync.WaitGroup
	wg.Add(2)
	go transferData(torConn, clientConn, &wg, fmt.Sprintf("%s [CLIENT->TOR %s]", logPrefix, targetAddr))
	go transferData(clientConn, torConn, &wg, fmt.Sprintf("%s [TOR->CLIENT %s]", logPrefix, targetAddr))
	wg.Wait()

	fmt.Printf("%s Túnel cerrado para '%s'.\n", logPrefix, targetAddr)
}

func main() {
	caddyBackendURL, err := url.Parse(caddyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al parsear la URL del backend de Caddy '%s': %v\n", caddyAddr, err)
		os.Exit(1)
	}
	if caddyBackendURL.Scheme == "" || caddyBackendURL.Host == "" {
		fmt.Fprintf(os.Stderr, "La URL del backend de Caddy '%s' debe incluir esquema (http/https) y host\n", caddyAddr)
		os.Exit(1)
	}

	fmt.Printf("Cargando certificado TLS desde: %s y %s\n", tlsCertFile, tlsKeyFile)
	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error CRÍTICO al cargar certificado/clave TLS desde '%s' y '%s': %v\n", tlsCertFile, tlsKeyFile, err)
		fmt.Fprintln(os.Stderr, "Asegúrate de que los archivos existen, son válidos y tienen los permisos correctos.")
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"http/1.1"}, // <-- *** LA CORRECCIÓN PRINCIPAL ESTÁ AQUÍ ***
	}

	handler := NewDualPurposeHandler(torSOCKSAddr, caddyBackendURL)

	server := &http.Server{
		Addr:              ":" + listenPort,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(os.Stderr, "HTTPS Server: ", log.LstdFlags),
	}

	fmt.Printf("Servidor HTTPS dual iniciado en [::]:%s (Forzando HTTP/1.1)\n", listenPort) // Log modificado
	fmt.Printf("- Solicitudes CONNECT reenviadas a SOCKS5: %s\n", torSOCKSAddr)
	fmt.Printf("- Otras solicitudes reenviadas a Caddy: %s\n", caddyAddr)

	err = server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error fatal del servidor HTTPS: %v\n", err)
		os.Exit(1)
	} else if err == http.ErrServerClosed {
		fmt.Println("Servidor HTTPS detenido limpiamente.")
	}
}

func transferData(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup, directionLabel string) {
	defer wg.Done()

	buf := make([]byte, 32*1024)
	bytesCopied, err := io.CopyBuffer(dst, src, buf)

	logPrefix := directionLabel

	if err != nil {
		netErr, isNetErr := err.(net.Error)
		opErr, isOpErr := err.(*net.OpError)
		shouldLogAsError := true
		if err == io.EOF || (isNetErr && netErr.Timeout()) ||
			(isOpErr && (strings.Contains(opErr.Err.Error(), "use of closed network connection") ||
				strings.Contains(opErr.Err.Error(), "connection reset by peer") ||
				strings.Contains(opErr.Err.Error(), "broken pipe"))) ||
			strings.Contains(err.Error(), "tls: use of closed connection") {
			shouldLogAsError = false
		}
		if shouldLogAsError {
			fmt.Fprintf(os.Stderr, "%s: Error durante copia (%d bytes): %T %v\n", logPrefix, bytesCopied, err, err)
		}
	}

	type closeWriter interface{ CloseWrite() error }
	if cw, ok := dst.(closeWriter); ok {
		cw.CloseWrite()
	}

	type closeReader interface{ CloseRead() error }
	if cr, ok := src.(closeReader); ok {
		cr.CloseRead()
	}
}
