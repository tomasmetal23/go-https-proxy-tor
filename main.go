package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/proxy"
)

var (
	listenPort   string
	torSOCKSAddr string
	tlsCertFile  string
	tlsKeyFile   string
)

func init() {
	listenPort = getEnv("LISTEN_PORT", "8443") // Usar un puerto > 1024 para pruebas sin root
	torSOCKSAddr = net.JoinHostPort(getEnv("TOR_SOCKS_HOST", "127.0.0.1"), getEnv("TOR_SOCKS_PORT", "9050"))
	tlsCertFile = getEnv("TLS_CERT_FILE", "./server.crt") // Rutas relativas para prueba fácil
	tlsKeyFile = getEnv("TLS_KEY_FILE", "./server.key")   // Rutas relativas para prueba fácil

	// Generar cert/key si no existen (solo para desarrollo fácil)
	generateSelfSignedCert()
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// --- Funciones para generar Certificado Autofirmado (para desarrollo) ---
func generateSelfSignedCert() {
	// (Opcional pero útil) - Puedes añadir aquí el código para generar
	// server.crt y server.key si no existen usando crypto/x509, etc.
	// O simplemente generarlos manualmente con openssl:
	// openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj "/CN=localhost"
	if _, err := os.Stat(tlsCertFile); os.IsNotExist(err) {
		fmt.Printf("Advertencia: Archivo de certificado '%s' no encontrado.\n", tlsCertFile)
		fmt.Println("Puedes generar uno con: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj \"/CN=localhost\"")
	}
	if _, err := os.Stat(tlsKeyFile); os.IsNotExist(err) {
		fmt.Printf("Advertencia: Archivo de clave '%s' no encontrado.\n", tlsKeyFile)
	}
}

// --- Fin de Funciones de Certificado ---

func main() {
	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al cargar certificado/clave TLS desde '%s' y '%s': %v\n", tlsCertFile, tlsKeyFile, err)
		fmt.Fprintln(os.Stderr, "Asegúrate de que los archivos existen y son válidos.")
		os.Exit(1)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Buena práctica
	}

	listener, err := tls.Listen("tcp", ":"+listenPort, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al escuchar en [::]:%s (TLS): %v\n", listenPort, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Proxy HTTPS escuchando en [::]:%s (reenviando a SOCKS5 %s)\n", listenPort, torSOCKSAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error al aceptar conexión TLS: %v\n", err)
			continue
		}
		// Manejar cada conexión en su propia goroutine
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	fmt.Printf("Nueva conexión TLS desde: %s\n", clientConn.RemoteAddr())

	// Usar bufio.Reader para leer la solicitud línea por línea
	reader := bufio.NewReader(clientConn)
	tpReader := textproto.NewReader(reader) // Para leer cabeceras MIME

	// Leer la línea de solicitud (ej: CONNECT example.com:443 HTTP/1.1)
	requestLine, err := tpReader.ReadLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Error al leer la línea de solicitud: %v\n", clientConn.RemoteAddr(), err)
		return
	}

	// Parsear la línea de solicitud
	method, requestURI, proto, ok := parseRequestLine(requestLine)
	if !ok {
		fmt.Fprintf(os.Stderr, "[%s] Línea de solicitud mal formada: %s\n", clientConn.RemoteAddr(), requestLine)
		sendErrorResponse(clientConn, 400, "Bad Request") // 400 Bad Request
		return
	}

	// Leer las cabeceras (y descartarlas por ahora, podrías usarlas para autenticación)
	_, err = tpReader.ReadMIMEHeader()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Error al leer cabeceras: %v\n", clientConn.RemoteAddr(), err)
		sendErrorResponse(clientConn, 400, "Bad Request")
		return
	}

	fmt.Printf("[%s] Solicitud: %s %s %s\n", clientConn.RemoteAddr(), method, requestURI, proto)

	// Este proxy SOLO maneja CONNECT para tunelizar
	if method != "CONNECT" {
		fmt.Fprintf(os.Stderr, "[%s] Método no soportado: %s\n", clientConn.RemoteAddr(), method)
		sendErrorResponse(clientConn, 405, "Method Not Allowed") // 405 Method Not Allowed
		return
	}

	// El requestURI para CONNECT es el host:port destino
	targetAddr := requestURI
	// Asegurarse de que el puerto esté presente (normalmente lo está para CONNECT)
	if !strings.Contains(targetAddr, ":") {
		fmt.Fprintf(os.Stderr, "[%s] Destino CONNECT sin puerto: %s\n", clientConn.RemoteAddr(), targetAddr)
		sendErrorResponse(clientConn, 400, "Bad Request")
		return
	}

	// --- Intentar conectar al destino via SOCKS5 (Tor) ---
	fmt.Printf("[%s] Intentando conectar a '%s' via SOCKS5 (%s)\n", clientConn.RemoteAddr(), targetAddr, torSOCKSAddr)

	// Usar golang.org/x/net/proxy para manejar SOCKS5 fácilmente
	dialer, err := proxy.SOCKS5("tcp", torSOCKSAddr, nil, proxy.Direct) // proxy.Direct significa que el dialer SOCKS no usa otro proxy
	if err != nil {
		// Esto no debería fallar normalmente, es solo configuración
		fmt.Fprintf(os.Stderr, "[%s] Error creando el dialer SOCKS5: %v\n", clientConn.RemoteAddr(), err)
		sendErrorResponse(clientConn, 500, "Internal Server Error")
		return
	}

	// Intentar la conexión SOCKS5 al destino final
	torConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Error al conectar a '%s' via SOCKS5 (%s): %v\n", clientConn.RemoteAddr(), targetAddr, torSOCKSAddr, err)
		// Traducir el error de SOCKS a un error HTTP adecuado
		// (Esto es simplificado, los errores de SOCKS son más específicos)
		sendErrorResponse(clientConn, 502, "Bad Gateway") // 502 Bad Gateway es común para errores de proxy
		return
	}
	defer torConn.Close() // Asegurarse de cerrar la conexión a Tor

	fmt.Printf("[%s] Conexión SOCKS5 establecida a '%s'\n", clientConn.RemoteAddr(), targetAddr)

	// --- Conexión SOCKS5 exitosa, informar al cliente ---
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Error al enviar '200 Connection established': %v\n", clientConn.RemoteAddr(), err)
		return // No podemos continuar si no podemos responder al cliente
	}

	fmt.Printf("[%s] Respuesta '200 OK' enviada. Iniciando túnel bidireccional.\n", clientConn.RemoteAddr())

	// --- Iniciar el túnel bidireccional ---
	// Copiar datos del cliente -> Tor en una goroutine
	// Copiar datos de Tor -> cliente en la goroutine actual (bloqueante)
	var wg sync.WaitGroup
	wg.Add(2) // Esperaremos a que ambas copias terminen

	go transferData(torConn, clientConn, &wg, "CLIENT->TOR")
	go transferData(clientConn, torConn, &wg, "TOR->CLIENT")

	// Esperar a que ambas direcciones del túnel terminen de copiar
	wg.Wait()

	fmt.Printf("[%s] Túnel cerrado para '%s'.\n", clientConn.RemoteAddr(), targetAddr)
}

// parseRequestLine divide la línea de solicitud HTTP en método, URI y protocolo.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	// Validar un poco el formato (simplificado)
	if parts[0] == "" || parts[1] == "" || parts[2] == "" || !strings.HasPrefix(parts[2], "HTTP/") {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// sendErrorResponse envía una respuesta de error HTTP simple al cliente.
func sendErrorResponse(conn net.Conn, statusCode int, statusText string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", statusCode, statusText)
	_, err := conn.Write([]byte(response))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Error al enviar respuesta de error (%d %s): %v\n", conn.RemoteAddr(), statusCode, statusText, err)
	}
}

// transferData copia datos de src a dst y decrementa el WaitGroup al terminar.
// También cierra ambas conexiones si hay un error o EOF para asegurar que el túnel se rompa.
func transferData(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup, direction string) {
	defer wg.Done() // Indicar que esta goroutine ha terminado
	// defer dst.Close() // No cerrar aquí directamente, io.Copy puede cerrar
	// defer src.Close() // Dejar que los defers en handleConnection lo hagan

	fmt.Printf("[%s] Iniciando copia %s\n", src.(net.Conn).RemoteAddr(), direction)
	// io.Copy maneja EOF automáticamente. Devuelve error si algo falla.
	bytesCopied, err := io.Copy(dst, src)
	if err != nil {
		// Ignorar errores comunes de conexión cerrada por el otro lado
		if !strings.Contains(err.Error(), "use of closed network connection") && err != io.EOF {
			fmt.Fprintf(os.Stderr, "[%s] Error durante copia %s (%d bytes): %v\n", src.(net.Conn).RemoteAddr(), direction, bytesCopied, err)
		}
	} else {
		fmt.Printf("[%s] Copia %s finalizada (%d bytes)\n", src.(net.Conn).RemoteAddr(), direction, bytesCopied)
	}

	// Intenta cerrar la conexión de escritura para señalar al otro lado que hemos terminado.
	// Esto ayuda a que el otro io.Copy termine si estaba esperando datos.
	// Podría ser dst.CloseWrite() en TCPConn, pero Close() es más general.
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	} else if tlsConn, ok := dst.(*tls.Conn); ok {
		tlsConn.CloseWrite()
	} else {
		// Para otros tipos, un Close completo podría ser la única opción,
		// aunque podría cortar la lectura prematuramente.
		// dst.Close()
	}
	// También cerramos la lectura para liberar recursos inmediatamente
	if tcpConn, ok := src.(*net.TCPConn); ok {
		tcpConn.CloseRead()
	}
	// No cerramos explícitamente aquí porque el defer en handleConnection lo hará,
	// y queremos asegurarnos de que ambas mitades del túnel se cierren juntas.
}
