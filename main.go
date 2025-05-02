package main

import (
	"context"
	"crypto/subtle" // For constant-time credential comparison
	"crypto/tls"
	"encoding/base64" // For decoding Basic Authentication
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil" // For the reverse proxy
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy" // For SOCKS5 client
)

// Global variables to hold configuration, mostly read from environment variables.
var (
	listenPort    string // Port to listen on for HTTPS connections
	torSOCKSAddr  string // Address (host:port) of the Tor SOCKS5 proxy
	tlsCertFile   string // Path to the TLS certificate file (.crt)
	tlsKeyFile    string // Path to the TLS private key file (.key)
	caddyAddr     string // URL of the backend web server (e.g., Caddy) for reverse proxying
	proxyUser     string // Username for proxy authentication (if empty, auth is disabled)
	proxyPassword string // Password for proxy authentication
)

// init function runs before main() to initialize global variables from environment.
func init() {
	listenPort = getEnv("LISTEN_PORT", "8443")
	torSOCKSAddr = net.JoinHostPort(getEnv("TOR_SOCKS_HOST", "127.0.0.1"), getEnv("TOR_SOCKS_PORT", "9050"))
	tlsCertFile = getEnv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt") // Default path, often used when mounting certs
	tlsKeyFile = getEnv("TLS_KEY_FILE", "/etc/ssl/private/server.key") // Default path
	caddyAddr = getEnv("CADDY_BACKEND_ADDR", "http://localhost:80")    // Default backend address

	// Read proxy credentials from environment. Authentication is enabled only if PROXY_USER is set.
	proxyUser = os.Getenv("PROXY_USER")
	proxyPassword = os.Getenv("PROXY_PASSWORD")

	if proxyUser != "" {
		fmt.Println("INFO: Proxy authentication ENABLED.")
		if proxyPassword == "" {
			// Warn if user is set but password is not (not recommended)
			fmt.Println("WARNING: PROXY_USER is set, but PROXY_PASSWORD is empty.")
		}
	} else {
		fmt.Println("INFO: Proxy authentication DISABLED (PROXY_USER not set).")
	}
}

// getEnv retrieves an environment variable or returns a default value if not set.
func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// --- Proxy Handler ---

// DualPurposeHandler holds the necessary components for handling both proxy and reverse proxy requests.
type DualPurposeHandler struct {
	TorSocksAddr string                 // Tor SOCKS address needed for tunneling
	CaddyProxy   *httputil.ReverseProxy // The reverse proxy instance for non-CONNECT requests
}

// NewDualPurposeHandler creates and configures a new DualPurposeHandler.
func NewDualPurposeHandler(torAddr string, caddyBackendURL *url.URL) *DualPurposeHandler {
	// Create the reverse proxy targeting the backend URL (e.g., Caddy)
	caddyProxy := httputil.NewSingleHostReverseProxy(caddyBackendURL)

	// Store the original director function
	originalDirector := caddyProxy.Director
	// Customize the director to add X-Forwarded-* headers
	caddyProxy.Director = func(req *http.Request) {
		originalDirector(req) // Run the default director logic first (sets Scheme, Host etc.)
		// Get the original client IP address
		clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			clientIP = req.RemoteAddr // Use the full RemoteAddr if split fails
		}
		// Set standard proxy headers
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Forwarded-Proto", "https") // Our listener is always HTTPS
		// Preserve the original Host header if the backend needs it
		if req.Host != "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
		// Note: NewSingleHostReverseProxy sets req.Host to the backend host.
		// If Caddy needs the original Host, uncomment the following line:
		// req.Host = req.Header.Get("X-Forwarded-Host")
	}

	// Customize the error handler for the reverse proxy
	caddyProxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		// Log the error
		fmt.Fprintf(os.Stderr, "[%s] Reverse Proxy Error towards Caddy (%s): %v\n", req.RemoteAddr, caddyBackendURL.Host, err)
		// Check if the client disconnected while handling the error
		select {
		case <-req.Context().Done():
			fmt.Fprintf(os.Stderr, "[%s] Client disconnected during reverse proxy error handling.\n", req.RemoteAddr)
			return
		default:
			// Try to send a 502 Bad Gateway response, but only if headers haven't been written yet.
			// This check is imperfect but prevents most "superfluous response.WriteHeader call" panics.
			headerMap := rw.Header()
			if headerMap.Get("Content-Type") == "" && headerMap.Get("Content-Length") == "" {
				rw.WriteHeader(http.StatusBadGateway)
			} else {
				fmt.Fprintf(os.Stderr, "[%s] Headers potentially already written, cannot send 502 for reverse proxy error.\n", req.RemoteAddr)
			}
		}
	}

	return &DualPurposeHandler{
		TorSocksAddr: torAddr,
		CaddyProxy:   caddyProxy,
	}
}

// checkProxyAuth validates the Proxy-Authorization header for CONNECT requests.
// It returns true if authentication succeeds or is disabled.
// It returns false and writes the appropriate 407 or 400 response if auth fails.
func checkProxyAuth(w http.ResponseWriter, r *http.Request) bool {
	// If PROXY_USER is not set in the environment, authentication is disabled.
	if proxyUser == "" {
		return true // Authentication passed (as it's off)
	}

	// Get the Proxy-Authorization header from the request.
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		// No credentials sent by the client, demand authentication.
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`) // Send challenge
		w.WriteHeader(http.StatusProxyAuthRequired)                      // 407 status code
		logPrefix := fmt.Sprintf("[%s %s %s %s]", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
		fmt.Printf("%s Proxy authentication required (407 sent)\n", logPrefix)
		return false // Authentication failed
	}

	// Check if the header starts with "Basic "
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		// Invalid format. Use helper as headers might have been written (Proxy-Authenticate).
		writeHTTPError(w, fmt.Sprintf("[%s]", r.RemoteAddr), "Bad Request: Invalid Proxy-Authorization header format", http.StatusBadRequest)
		fmt.Printf("[%s %s %s %s] Error: Invalid Proxy-Authorization format: %s\n", r.RemoteAddr, r.Method, r.Host, r.URL.Path, authHeader)
		return false // Authentication failed
	}

	// Decode the Base64 encoded "username:password" string.
	encoded := authHeader[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Invalid Base64 encoding.
		writeHTTPError(w, fmt.Sprintf("[%s]", r.RemoteAddr), "Bad Request: Invalid Base64 encoding in Proxy-Authorization", http.StatusBadRequest)
		fmt.Printf("[%s %s %s %s] Error: Invalid Base64 in Proxy-Authorization: %v\n", r.RemoteAddr, r.Method, r.Host, r.URL.Path, err)
		return false // Authentication failed
	}

	// Split the decoded string into username and password.
	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		// Invalid "username:password" format.
		writeHTTPError(w, fmt.Sprintf("[%s]", r.RemoteAddr), "Bad Request: Invalid username:password format in Proxy-Authorization", http.StatusBadRequest)
		fmt.Printf("[%s %s %s %s] Error: Invalid user:pass format in Proxy-Authorization\n", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
		return false // Authentication failed
	}

	providedUser := parts[0]
	providedPassword := parts[1]

	// Compare the provided credentials with the configured ones using constant-time comparison
	// to prevent timing attacks. subtle.ConstantTimeCompare returns 1 if equal, 0 otherwise.
	userMatch := subtle.ConstantTimeCompare([]byte(providedUser), []byte(proxyUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(providedPassword), []byte(proxyPassword)) == 1

	if userMatch && passMatch {
		// Authentication successful. Log message removed here for cleaner logs, handled implicitly by proceeding.
		return true // Authentication successful
	}

	// Invalid credentials provided.
	logPrefix := fmt.Sprintf("[%s %s %s %s]", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
	fmt.Printf("%s Proxy authentication failed for user '%s'\n", logPrefix, providedUser)
	w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`) // Re-send challenge
	w.WriteHeader(http.StatusProxyAuthRequired)                      // 407 status code
	return false                                                     // Authentication failed
}

// ServeHTTP is the main entry point for incoming HTTP requests.
// It decides whether to handle the request as a CONNECT tunnel or a reverse proxy request.
func (h *DualPurposeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a prefix for logging, includes client address and request details.
	logPrefix := fmt.Sprintf("[%s %s %s %s]", r.RemoteAddr, r.Method, r.Host, r.URL.Path)
	fmt.Printf("%s Received request\n", logPrefix)

	// Check if the request method is CONNECT.
	if r.Method == http.MethodConnect {
		// --- NEW: Check proxy authentication FIRST for CONNECT requests ---
		if !checkProxyAuth(w, r) {
			// If checkProxyAuth returned false, it already sent the 407 or 400 response. Just return.
			return
		}
		// --- END Authentication Check ---

		// If authentication passed (or was disabled), proceed to handle the tunnel.
		h.handleTunnel(w, r, logPrefix)

	} else {
		// For all other methods (GET, POST, etc.), forward the request to the backend (Caddy).
		// No proxy authentication is applied to these requests.
		fmt.Printf("%s Forwarding request to Caddy (%s)\n", logPrefix, caddyAddr)
		h.CaddyProxy.ServeHTTP(w, r)
	}
}

// handleTunnel processes CONNECT requests *after* successful authentication.
// It establishes the SOCKS5 tunnel via Tor and hijacks the client connection.
func (h *DualPurposeHandler) handleTunnel(w http.ResponseWriter, r *http.Request, logPrefix string) {
	// The target address (host:port) is in the request URL's Host field for CONNECT.
	targetAddr := r.URL.Host
	// Logging "CONNECT request for..." is now implicitly covered by the logPrefix in ServeHTTP

	// Double-check if the target address includes a port (should always for CONNECT).
	if !strings.Contains(targetAddr, ":") {
		errMsg := "CONNECT target must include port (post-auth check)"
		fmt.Fprintf(os.Stderr, "%s Error: %s (%s)\n", logPrefix, errMsg, targetAddr)
		// Try to send a 400 error if possible, otherwise just close connection.
		writeHTTPError(w, logPrefix, errMsg, http.StatusBadRequest)
		return
	}

	// --- Attempt to connect to the target via Tor SOCKS5 proxy ---
	fmt.Printf("%s Authenticated. Attempting to connect to '%s' via SOCKS5 (%s)\n", logPrefix, targetAddr, h.TorSocksAddr)
	// Create a SOCKS5 dialer using the configured Tor address. proxy.Direct means the SOCKS dialer itself doesn't use another proxy.
	dialer, err := proxy.SOCKS5("tcp", h.TorSocksAddr, nil, proxy.Direct)
	if err != nil {
		// This is an internal server error (config issue likely).
		fmt.Fprintf(os.Stderr, "%s Error creating SOCKS5 dialer: %v\n", logPrefix, err)
		writeHTTPError(w, logPrefix, "Internal Server Error (SOCKS dialer)", http.StatusInternalServerError)
		return
	}

	// Set a timeout for the SOCKS connection attempt.
	dialContext, cancel := context.WithTimeout(context.Background(), 60*time.Second) // 60 second timeout
	defer cancel()                                                                   // Ensure the context is cancelled to release resources

	// Check if the dialer supports context dialing (it should).
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s Error: SOCKS5 dialer does not support DialContext\n", logPrefix)
		writeHTTPError(w, logPrefix, "Internal Server Error (SOCKS dialer context)", http.StatusInternalServerError)
		return
	}

	// Perform the SOCKS5 dial to the target address with the timeout context.
	torConn, err := contextDialer.DialContext(dialContext, "tcp", targetAddr)
	if err != nil {
		// Failed to connect via Tor.
		fmt.Fprintf(os.Stderr, "%s Error connecting to '%s' via SOCKS5 (%s): %v\n", logPrefix, targetAddr, h.TorSocksAddr, err)
		errMsg := fmt.Sprintf("Bad Gateway: SOCKS connection to '%s' failed", targetAddr)
		statusCode := http.StatusBadGateway // Default to 502
		// Check if the error was a timeout.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			errMsg = fmt.Sprintf("Gateway Timeout: SOCKS connection to '%s' timed out", targetAddr)
			statusCode = http.StatusGatewayTimeout // Use 504 for timeouts
		}
		// Send the appropriate error back to the client.
		writeHTTPError(w, logPrefix, errMsg, statusCode)
		return
	}
	// Ensure the connection to Tor is closed when this function exits.
	defer torConn.Close()
	fmt.Printf("%s SOCKS5 connection established to '%s'\n", logPrefix, targetAddr)

	// --- Hijack the client's connection ---
	// We need direct access to the underlying TCP/TLS connection to relay raw data.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// This should not happen with HTTP/1.1 forced, but check just in case.
		fmt.Fprintf(os.Stderr, "%s CRITICAL Error: ResponseWriter does NOT support Hijacking.\n", logPrefix)
		torConn.Close() // Close the Tor connection we opened.
		// Cannot reliably send an HTTP error anymore.
		return
	}

	// Get the raw network connection from the ResponseWriter.
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error hijacking client connection: %v\n", logPrefix, err)
		torConn.Close()
		return
	}
	// Ensure the client connection is closed when this function exits.
	defer clientConn.Close()
	// Logging successful hijack removed, implicit if no error occurred.

	// --- Send success response to the client ---
	// Write the standard "200 Connection established" response directly to the hijacked connection.
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Error sending '200 Connection established': %v\n", logPrefix, err)
		// Cannot proceed if we can't signal success to the client.
		return
	}

	fmt.Printf("%s Tunnel '200 OK' sent. Starting data transfer.\n", logPrefix)

	// --- Start bidirectional data transfer ---
	// Use a WaitGroup to wait for both copy directions to finish.
	var wg sync.WaitGroup
	wg.Add(2)
	// Start goroutine to copy data from Tor SOCKS connection to the client.
	go transferData(clientConn, torConn, &wg, fmt.Sprintf("%s [TOR->CLIENT %s]", logPrefix, targetAddr))
	// Start goroutine to copy data from the client to the Tor SOCKS connection.
	go transferData(torConn, clientConn, &wg, fmt.Sprintf("%s [CLIENT->TOR %s]", logPrefix, targetAddr))

	// Wait until both copy operations are done.
	wg.Wait()

	fmt.Printf("%s Tunnel closed for '%s'.\n", logPrefix, targetAddr)
}

// writeHTTPError is a helper function to safely attempt writing an HTTP error response.
// It's needed because calling http.Error after potentially writing other headers (like Proxy-Authenticate)
// can cause panics.
func writeHTTPError(w http.ResponseWriter, logPrefix, message string, statusCode int) {
	// Simple check: If essential headers haven't been set, it's likely safe to write.
	headerMap := w.Header()
	if headerMap.Get("Content-Type") == "" && headerMap.Get("Content-Length") == "" && headerMap.Get("Proxy-Authenticate") == "" {
		// Use the standard http.Error function.
		http.Error(w, message, statusCode)
	} else {
		// Headers were likely already written (e.g., 407 challenge).
		// Log the error and attempt to close the underlying connection as a last resort.
		fmt.Fprintf(os.Stderr, "%s: Could not send HTTP error '%s' (%d) to client, headers might already be written.\n", logPrefix, message, statusCode)
		if hijacker, ok := w.(http.Hijacker); ok {
			conn, _, err := hijacker.Hijack()
			if err == nil {
				fmt.Fprintf(os.Stderr, "%s: Force closing underlying connection due to post-write error.\n", logPrefix)
				conn.Close()
			}
		}
	}
}

// main is the application entry point.
func main() {
	// Parse the backend Caddy URL provided via environment variable.
	caddyBackendURL, err := url.Parse(caddyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing Caddy backend URL '%s': %v\n", caddyAddr, err)
		os.Exit(1)
	}
	if caddyBackendURL.Scheme == "" || caddyBackendURL.Host == "" {
		fmt.Fprintf(os.Stderr, "Caddy backend URL '%s' must include scheme (http/https) and host\n", caddyAddr)
		os.Exit(1)
	}

	// Load the TLS certificate and key from the specified files.
	fmt.Printf("Loading TLS certificate from: %s and %s\n", tlsCertFile, tlsKeyFile)
	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		// This is a fatal error, the server cannot start without valid certs.
		fmt.Fprintf(os.Stderr, "CRITICAL Error loading TLS certificate/key from '%s' and '%s': %v\n", tlsCertFile, tlsKeyFile, err)
		os.Exit(1)
	}

	// Configure TLS settings for the server.
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},                  // Server certificate
		MinVersion:       tls.VersionTLS12,                         // Minimum TLS version
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, // Preferred elliptic curves
		// Strong, modern cipher suites
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// Force HTTP/1.1 via ALPN to ensure CONNECT hijacking works (HTTP/2 is incompatible).
		NextProtos: []string{"http/1.1"},
		// Explicitly disable client certificate authentication.
		ClientAuth: tls.NoClientCert,
	}

	// Create the custom handler that routes requests.
	handler := NewDualPurposeHandler(torSOCKSAddr, caddyBackendURL)

	// Configure the main HTTP server.
	server := &http.Server{
		Addr:      ":" + listenPort, // Listen on all interfaces on the specified port
		Handler:   handler,          // Use our custom handler
		TLSConfig: tlsConfig,        // Apply the TLS configuration
		// Set reasonable timeouts to prevent resource exhaustion.
		ReadTimeout:       15 * time.Second,                                    // Max time to read the entire request, including body
		ReadHeaderTimeout: 10 * time.Second,                                    // Max time to read request headers
		WriteTimeout:      30 * time.Second,                                    // Max time to write the response
		IdleTimeout:       120 * time.Second,                                   // Max time for an idle connection (keep-alive)
		ErrorLog:          log.New(os.Stderr, "HTTPS Server: ", log.LstdFlags), // Log server errors
	}

	// Print startup messages.
	fmt.Printf("Dual-purpose HTTPS server started on [::]:%s (Forcing HTTP/1.1)\n", listenPort)
	if proxyUser != "" {
		fmt.Printf("- Proxy authentication REQUIRED for CONNECT requests\n")
	} else {
		fmt.Printf("- Proxy authentication NOT required for CONNECT requests\n")
	}
	fmt.Printf("- Authenticated CONNECT requests forwarded to SOCKS5: %s\n", torSOCKSAddr)
	fmt.Printf("- Other requests forwarded to Caddy backend: %s\n", caddyAddr)

	// Start the HTTPS server. This blocks until the server is shut down.
	err = server.ListenAndServeTLS(tlsCertFile, tlsKeyFile)
	if err != nil && err != http.ErrServerClosed {
		// Fatal error during server operation.
		fmt.Fprintf(os.Stderr, "Fatal HTTPS server error: %v\n", err)
		os.Exit(1)
	} else if err == http.ErrServerClosed {
		// Server shut down gracefully.
		fmt.Println("HTTPS server stopped cleanly.")
	}
}

// transferData copies data between two connections (source and destination)
// in one direction. It's typically run in two separate goroutines for
// bidirectional transfer. It decrements the WaitGroup when done.
func transferData(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup, directionLabel string) {
	// Ensure Done is called on the WaitGroup when this goroutine finishes.
	defer wg.Done()

	// Use a buffer for potentially better performance.
	buf := make([]byte, 32*1024) // 32KB buffer
	// Copy data from source to destination until EOF or error.
	bytesCopied, err := io.CopyBuffer(dst, src, buf)

	logPrefix := directionLabel // Label already contains useful context

	// Handle potential errors during the copy operation.
	if err != nil {
		// Check if the error is a common, expected network closure error.
		netErr, isNetErr := err.(net.Error)
		opErr, isOpErr := err.(*net.OpError)
		shouldLogAsError := true // Assume we should log it as an error initially
		// Don't log expected errors like EOF or normal connection closures as errors.
		if err == io.EOF ||
			(isNetErr && netErr.Timeout()) ||
			(isOpErr && (strings.Contains(opErr.Err.Error(), "use of closed network connection") ||
				strings.Contains(opErr.Err.Error(), "connection reset by peer") ||
				strings.Contains(opErr.Err.Error(), "broken pipe"))) ||
			strings.Contains(err.Error(), "tls: use of closed connection") {
			shouldLogAsError = false
		}

		// Log unexpected errors.
		if shouldLogAsError {
			fmt.Fprintf(os.Stderr, "%s: Error during copy (%d bytes): %T %v\n", logPrefix, bytesCopied, err, err)
		}
		// Optional: Log expected closures verbosely if needed for debugging
		// else {
		//     fmt.Printf("%s: Copy finished (%d bytes), expected closure: %v\n", logPrefix, bytesCopied, err)
		// }
	}
	// Optional: Log successful copy completion verbosely
	// if bytesCopied > 0 {
	// 	fmt.Printf("%s: Copy finished (%d bytes)\n", logPrefix, bytesCopied)
	// }

	// Try to signal the end of writing/reading to potentially speed up tunnel closure.
	// Close the write-side of the destination connection, if possible (signals EOF to the reader on the other side).
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite() // Ignore error, best effort
	}

	// Close the read-side of the source connection, if possible (releases resources).
	type closeReader interface{ CloseRead() error }
	if cr, ok := src.(closeReader); ok {
		_ = cr.CloseRead() // Ignore error, best effort
	}
	// Note: We don't call dst.Close() or src.Close() here; the main defer statements
	// in handleTunnel will handle the full connection closure.
}
