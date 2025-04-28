package main

import (
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
	tlsCertFile = getEnv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt") // Ruta más común para certs montados
	tlsKeyFile = getEnv("TLS_KEY_FILE", "/etc/ssl/private/server.key") // Ruta más común para keys montadas
	caddyAddr = getEnv("CADDY_BACKEND_ADDR", "http://caddy:80")

	// Ya no se llama a generateSelfSignedCert()
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// --- La función generateSelfSignedCert() ha sido eliminada ---

// --- Proxy Handler ---

// DualPurposeHandler maneja tanto solicitudes CONNECT (proxy Tor) como solicitudes web normales (reverse proxy a Caddy)
type DualPurposeHandler struct {
	TorSocksAddr string
	CaddyProxy   *httputil.ReverseProxy
}

func NewDualPurposeHandler(torAddr string, caddyBackendURL *url.URL) *DualPurposeHandler {
	// Crea el reverse proxy para Caddy
	caddyProxy := httputil.NewSingleHostReverseProxy(caddyBackendURL)

	// (Opcional pero recomendado) Modifica el director para establecer cabeceras como X-Forwarded-For
	originalDirector := caddyProxy.Director
	caddyProxy.Director = func(req *http.Request) {
		originalDirector(req) // Ejecuta el director original (establece Scheme, Host, etc.)
		// Establece la IP original del cliente
		// Primero obtiene la IP real, manejando casos como "ip:port"
		clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			clientIP = req.RemoteAddr // Usar la dirección completa si SplitHostPort falla
		}
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Forwarded-Proto", "https") // Porque nuestro listener es TLS
		// Preservar el Host original si Caddy está configurado para usarlo
		if req.Host != "" { // Asegurarse de que el Host original esté presente
			req.Header.Set("X-Forwarded-Host", req.Host)
		}

		// Asegúrate de que el Host enviado a Caddy sea el esperado por Caddy
		// NewSingleHostReverseProxy establece req.Host = caddyBackendURL.Host por defecto.
		// Descomenta la siguiente línea si Caddy necesita el Host original (ej: tor.saiyans.com.ve)
		// req.Host = req.Header.Get("X-Forwarded-Host")
	}

	// (Opcional) Personalizar el manejo de errores del ReverseProxy
	caddyProxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		fmt.Fprintf(os.Stderr, "[%s] Reverse Proxy Error hacia Caddy (%s): %v\n", req.RemoteAddr, caddyBackendURL.Host, err)
		rw.WriteHeader(http.StatusBadGateway) // 502 es apropiado si el backend falla
	}


	return &DualPurposeHandler{
		TorSocksAddr: torAddr,
		CaddyProxy:   caddyProxy,
	}
}

// ServeHTTP es el corazón del handler. Decide qué hacer con cada solicitud.
func (h *DualPurposeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logPrefix := fmt.Sprintf("[%s %s %s %s]", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
	fmt.Printf("%s Recibida solicitud\n", logPrefix)


	if r.Method == http.MethodConnect {
		// Es una solicitud de proxy CONNECT -> Manejar túnel a Tor
		h.handleTunnel(w, r, logPrefix) // Pasar logPrefix para consistencia
	} else {
		// Es una solicitud web normal (GET, POST, etc.) -> Reenviar a Caddy
		fmt.Printf("%s Reenviando solicitud a Caddy (%s)\n", logPrefix, h.CaddyProxy.ErrorHandler) // Mostrando config ErrorHandler
		h.CaddyProxy.ServeHTTP(w, r)
	}
}

// handleTunnel maneja las solicitudes CONNECT
func (h *DualPurposeHandler) handleTunnel(w http.ResponseWriter, r *http.Request, logPrefix string) {
	targetAddr := r.URL.Host // Para CONNECT, r.URL.Host contiene "host:port"
	fmt.Printf("%s Solicitud CONNECT para: %s\n", logPrefix, targetAddr)

	// Validar que el targetAddr tenga puerto (ya lo hace http.Server, pero doble chequeo no hace daño)
	if !strings.Contains(targetAddr, ":") {
		errMsg := "CONNECT target must include port"
		http.Error(w, errMsg, http.StatusBadRequest)
		fmt.Fprintf(os.Stderr, "%s Error: %s (%s)\n", logPrefix, errMsg, targetAddr)
		return
	}

	// --- Intentar conectar al destino via SOCKS5 (Tor) ---
	fmt.Printf("%s Intentando conectar a '%s' via SOCKS5 (%s)\n", logPrefix, targetAddr, h.TorSocksAddr)
	dialer, err := proxy.SOCKS5("tcp", h.TorSocksAddr, nil, proxy.Direct)
	if err != nil {
		// Error interno configurando el dialer
		fmt.Fprintf(os.Stderr, "%s Error creando el dialer SOCKS5: %v\n", logPrefix, err)
		http.Error(w, "Internal Server Error (SOCKS dialer)", http.StatusInternalServerError)
		return
	}

	// Añadir un timeout razonable para la conexión SOCKS
	dialContext, cancel := context.WithTimeout(context.Background(), 30*time.Second) // 30 segundos timeout
	defer cancel()

	torConn, err := dialer.(proxy.ContextDialer).DialContext(dialContext, "tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error al conectar a '%s' via SOCKS5 (%s): %v\n", logPrefix, targetAddr, h.TorSocksAddr, err)
		// Usar 502 Bad Gateway para errores de conexión del proxy
		http.Error(w, fmt.Sprintf("Bad Gateway (SOCKS connection to %s failed)", targetAddr), http.StatusBadGateway)
		return
	}
	defer torConn.Close()
	fmt.Printf("%s Conexión SOCKS5 establecida a '%s'\n", logPrefix, targetAddr)

	// --- Secuestrar la conexión del cliente ---
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s Error: El ResponseWriter no soporta Hijacking\n", logPrefix)
		http.Error(w, "Internal Server Error (Hijacking not supported)", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error al hacer Hijack de la conexión: %v\n", logPrefix, err)
		torConn.Close() // Asegura cerrar la conexión a Tor si el hijack falla después de abrirla
		return
	}
	defer clientConn.Close()

	// --- Informar al cliente que el túnel está listo ---
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error al enviar '200 Connection established': %v\n", logPrefix, err)
		return // No podemos continuar
	}

	fmt.Printf("%s Respuesta '200 OK' enviada. Iniciando túnel bidireccional.\n", logPrefix)

	// --- Iniciar el túnel bidireccional ---
	var wg sync.WaitGroup
	wg.Add(2)
	// Pasar etiquetas más descriptivas a transferData
	go transferData(torConn, clientConn, &wg, fmt.Sprintf("%s [CLIENT->TOR %s]", logPrefix, targetAddr))
	go transferData(clientConn, torConn, &wg, fmt.Sprintf("%s [TOR->CLIENT %s]", logPrefix, targetAddr))
	wg.Wait()

	fmt.Printf("%s Túnel cerrado para '%s'.\n", logPrefix, targetAddr)
}

// --- Fin Proxy Handler ---

func main() {
	// Parsear la URL del backend de Caddy
	caddyBackendURL, err := url.Parse(caddyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al parsear la URL del backend de Caddy '%s': %v\n", caddyAddr, err)
		os.Exit(1)
	}
	if caddyBackendURL.Scheme == "" || caddyBackendURL.Host == "" {
		fmt.Fprintf(os.Stderr, "La URL del backend de Caddy '%s' debe incluir esquema (http/https) y host\n", caddyAddr)
		os.Exit(1)
	}

	// --- Cargar certificado TLS ---
	// Ahora esto fallará si los archivos no existen o son inválidos, que es lo deseado.
	fmt.Printf("Cargando certificado TLS desde: %s y %s\n", tlsCertFile, tlsKeyFile)
	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error CRÍTICO al cargar certificado/clave TLS desde '%s' y '%s': %v\n", tlsCertFile, tlsKeyFile, err)
		fmt.Fprintln(os.Stderr, "Asegúrate de que los archivos existen, son válidos y tienen los permisos correctos.")
		os.Exit(1) // Salir inmediatamente si no se pueden cargar los certificados
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, // Curvas modernas
		CipherSuites: []uint16{ // Suites de cifrado fuertes y modernas
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Crear el handler dual
	handler := NewDualPurposeHandler(torSOCKSAddr, caddyBackendURL)

	// Crear el servidor HTTP/S
	server := &http.Server{
		Addr:      ":" + listenPort,
		Handler:   handler,
		TLSConfig: tlsConfig,
		// Establecer timeouts más robustos
		ReadTimeout:       15 * time.Second, // Tiempo para leer toda la cabecera
		ReadHeaderTimeout: 10 * time.Second, // Tiempo para leer solo la cabecera
		WriteTimeout:      30 * time.Second, // Tiempo para escribir la respuesta
		IdleTimeout:       120 * time.Second, // Tiempo máximo para conexión inactiva (keep-alive)
		ErrorLog:          log.New(os.Stderr, "HTTPS Server: ", log.LstdFlags),
	}

	fmt.Printf("Servidor HTTPS dual iniciado en [::]:%s\n", listenPort)
	fmt.Printf("- Solicitudes CONNECT reenviadas a SOCKS5: %s\n", torSOCKSAddr)
	fmt.Printf("- Otras solicitudes reenviadas a Caddy: %s\n", caddyAddr)

	// Iniciar el servidor escuchando TLS
	err = server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error fatal del servidor HTTPS: %v\n", err)
		os.Exit(1)
	} else if err == http.ErrServerClosed {
		fmt.Println("Servidor HTTPS detenido limpiamente.")
	}
}

// transferData copia datos de src a dst y decrementa el WaitGroup al terminar.
func transferData(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup, directionLabel string) {
	defer wg.Done()

	// Usar io.CopyBuffer para potencialmente mejorar eficiencia con buffers
	buf := make([]byte, 32*1024) // Buffer de 32KB
	bytesCopied, err := io.CopyBuffer(dst, src, buf)

	logPrefix := directionLabel // La etiqueta ya contiene la info necesaria

	if err != nil {
		// Reducir el ruido de logs para errores "normales" de cierre
		netErr, isNetErr := err.(net.Error)
		opErr, isOpErr := err.(*net.OpError)

		shouldLogAsError := true
		if err == io.EOF {
			shouldLogAsError = false // EOF es normal al terminar una dirección
		} else if isNetErr && netErr.Timeout() {
			shouldLogAsError = false // Timeouts pueden ser normales
		} else if isOpErr && (strings.Contains(opErr.Err.Error(), "use of closed network connection") ||
							  strings.Contains(opErr.Err.Error(), "connection reset by peer") ||
							  strings.Contains(opErr.Err.Error(), "broken pipe")) {
			shouldLogAsError = false // Errores comunes de cierre de conexión
		} else if strings.Contains(err.Error(), "tls: use of closed connection") {
             shouldLogAsError = false // Específico de TLS al cerrar
        }


		if shouldLogAsError {
			fmt.Fprintf(os.Stderr, "%s: Error durante copia (%d bytes): %T %v\n", logPrefix, bytesCopied, err, err)
		} else {
			// Log informativo para cierres esperados
			// fmt.Printf("%s: Copia terminada (%d bytes), cierre esperado: %v\n", logPrefix, bytesCopied, err)
		}

	}

	if bytesCopied > 0 {
		// fmt.Printf("%s: Copia finalizada (%d bytes)\n", logPrefix, bytesCopied) // Log menos verboso
	}


	// Intentar cerrar escritura/lectura para señalizar fin y liberar recursos
    type closeWriter interface { CloseWrite() error }
    if cw, ok := dst.(closeWriter); ok {
        cw.CloseWrite()
    }

    type closeReader interface { CloseRead() error }
    if cr, ok := src.(closeReader); ok {
       cr.CloseRead()
    }
    // No hacer dst.Close() o src.Close() aquí; dejar que los defer originales lo hagan.
}

// Añadir import de context
import "context"