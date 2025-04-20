package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

const (
	listenPort    = "443" // Escucharemos en el puerto estándar de HTTPS
	torSOCKSProxy = "127.0.0.1:9050"
)

func main() {
	// Cargar el certificado y la clave
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
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

	// Servidor web simple (handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "¡Hola desde tu puente TLS a Tor!\n")
	})

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

	// Aquí es donde necesitaremos discriminar el tráfico.
	// Por ahora, simplemente intentamos servir la web.
	http.ServeConn(clientConn, &http.Server{})

	// En el futuro, aquí iría la lógica para detectar
	// si es una solicitud SOCKS5 o un CONNECT y, de ser así,
	// conectar a Tor y reenviar el tráfico.
}