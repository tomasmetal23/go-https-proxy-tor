package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	listenPort    string
	torSOCKSAddr  string
	caddyAddr     string
	tlsCertFile   string
	tlsKeyFile    string
)

func init() {
	listenPort = getEnv("LISTEN_PORT", "443")
	torSOCKSAddr = net.JoinHostPort(getEnv("TOR_SOCKS_HOST", "127.0.0.1"), getEnv("TOR_SOCKS_PORT", "9050"))
	caddyAddr = net.JoinHostPort(getEnv("CADDY_HOST", "caddy"), getEnv("CADDY_PORT", "80"))
	tlsCertFile = getEnv("TLS_CERT_FILE", "/app/server.crt")
	tlsKeyFile = getEnv("TLS_KEY_FILE", "/app/server.key")
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func main() {
	// Cargar el certificado y la clave
	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al cargar el certificado y la clave: %v\n", err)
		os.Exit(1)
	}

	// Configuración TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Crear el listener TLS
	listener, err := tls.Listen("tcp", ":"+listenPort, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al escuchar en el puerto %s (TLS): %v\n", listenPort, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Escuchando en el puerto %s (TLS)...\n", listenPort)

	// Bucle para aceptar conexiones TLS y manejarlas
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error al aceptar la conexión TLS: %v\n", err)
			continue
		}
		fmt.Printf("Nueva conexión TLS desde: %s\n", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Leer los primeros bytes de la solicitud para determinar el método
	buffer := make([]byte, 512)
	n, err := clientConn.Read(buffer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al leer la solicitud inicial del cliente: %v\n", err)
		return
	}

	request := string(buffer[:n])
	fmt.Printf("Solicitud recibida desde %s:\n%s\n", clientConn.RemoteAddr(), request)

	// Verificar el método HTTP
	if strings.HasPrefix(request, "GET") || strings.HasPrefix(request, "POST") || strings.HasPrefix(request, "HEAD") {
		// Parece una solicitud web normal, reenviar a Caddy
		fmt.Println("Detectada solicitud web, reenviando a Caddy...")
		forwardToCaddy(clientConn, request)
		return
	} else if strings.HasPrefix(request, "CONNECT") {
		// Parece una solicitud CONNECT para tunelización, manejar como proxy a Tor
		fmt.Println("Detectada solicitud CONNECT, manejando proxy a Tor...")
		handleTorProxy(clientConn, buffer[:n]) // Pasar el buffer inicial
		return
	} else {
		fmt.Println("Solicitud no reconocida, cerrando conexión.")
		return
	}
}

// Función para reenviar la conexión/solicitud a Caddy
func forwardToCaddy(clientConn net.Conn, request string) {
	caddyConn, err := net.Dial("tcp", caddyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al conectar a Caddy (%s): %v\n", caddyAddr, err)
		return
	}
	defer caddyConn.Close()

	_, err = caddyConn.Write([]byte(request))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al enviar la solicitud a Caddy: %v\n", err)
		return
	}

	copyData(clientConn, caddyConn)
}

// Función para manejar el proxy a Tor para solicitudes CONNECT
func handleTorProxy(clientConn net.Conn, initialRequest []byte) {
	torConn, err := net.Dial("tcp", torSOCKSAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al conectar al proxy SOCKS5 (%s): %v\n", torSOCKSAddr, err)
		return
	}
	defer torConn.Close()
	fmt.Printf("Conectado al proxy SOCKS5: %s para solicitud CONNECT desde %s\n", torSOCKSAddr, clientConn.RemoteAddr())

	bufioReader := bufio.NewReader(bytes.NewReader(initialRequest))
	req, err := http.ReadRequest(bufioReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al leer la solicitud CONNECT: %v\n", err)
		return
	}

	if req.URL == nil {
		fmt.Fprintf(os.Stderr, "URL nulo en la solicitud CONNECT\n")
		return
	}

	target := req.URL.Host
	if !strings.Contains(target, ":") {
		target += ":443" // Puerto por defecto para HTTPS
	}
	fmt.Printf("Destino de la conexión CONNECT: %s\n", target)

	// Implementación del protocolo SOCKS5

	// Paso 1: Saludo SOCKS5
	_, err = torConn.Write([]byte{0x05, 0x01, 0x00}) // Versión 5, 1 método, sin autenticación
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al enviar saludo SOCKS5: %v\n", err)
		return
	}
	response := make([]byte, 2)
	_, err = torConn.Read(response)
	if err != nil || response[0] != 0x05 || response[1] != 0x00 {
		fmt.Fprintf(os.Stderr, "Error en la respuesta del saludo SOCKS5: %v\n", err)
		return
	}

	// Paso 2: Solicitud de conexión SOCKS5
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al parsear el destino: %v\n", err)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al convertir el puerto a entero: %v\n", err)
		return
	}

	_, err = torConn.Write([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}) // VER, CMD=connect, RSV=0, ATYP=domain name
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al enviar la solicitud de conexión SOCKS5 (parte 1): %v\n", err)
		return
	}
	_, err = torConn.Write([]byte(host))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al enviar la solicitud de conexión SOCKS5 (host): %v\n", err)
		return
	}
	_, err = torConn.Write([]byte{byte(port >> 8), byte(port & 0xff)}) // Puerto en big-endian
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error al enviar la solicitud de conexión SOCKS5 (puerto): %v\n", err)
		return
	}

	// Paso 3: Leer la respuesta de la solicitud de conexión SOCKS5
	connectResponse := make([]byte, 10) // Mínimo tamaño de respuesta
	_, err = torConn.Read(connectResponse)
	if err != nil || connectResponse[0] != 0x05 || connectResponse[1] != 0x00 {
		fmt.Fprintf(os.Stderr, "Error en la respuesta de la solicitud de conexión SOCKS5: %v\n", err)
		return
	}

	// Paso 4: Reenviar datos bidireccionalmente
	go copyData(clientConn, torConn)
	copyData(torConn, clientConn)
}

func copyData(dst net.Conn, src net.Conn) (int64, error) {
	return io.Copy(dst, src)
}