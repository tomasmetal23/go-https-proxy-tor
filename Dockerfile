# Dockerfile para https-tor-proxy

# --- Etapa de Construcción ---
    FROM golang:1.24.2-alpine AS builder

    # Instalar git, necesario para descargar algunas dependencias de Go (como golang.org/x/...)
    RUN apk add --no-cache git
    
    # Establecer directorio de trabajo
    WORKDIR /src
    
    # Copiar archivos de módulos y descargar dependencias PRIMERO
    # Esto aprovecha el cache de Docker si los módulos no cambian
    COPY go.mod go.sum ./
    RUN go mod download
    
    # Copiar el resto del código fuente de la aplicación
    COPY . .
    
    # Compilar la aplicación estáticamente (sin CGO)
    # -ldflags="-w -s": Reduce el tamaño del binario eliminando información de debug y tabla de símbolos.
    # El "." al final indica que compile el paquete en el directorio actual.
    RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/go-https-proxy-tor .
    
    # --- Etapa Final (Imagen Mínima) ---
    FROM alpine:3.19
    
    # Instalar SOLO lo necesario para RUNTIME
    # ca-certificates: Para validar certificados si la app hiciera llamadas TLS salientes (buena práctica tenerlo).
    # tzdata: Para manejo correcto de zonas horarias si la app lo necesitara.
    RUN apk add --no-cache \
        ca-certificates \
        tzdata
    
    # Establecer directorio de trabajo
    WORKDIR /app
    
    # Copiar el binario compilado desde la etapa 'builder'
    COPY --from=builder /app/go-https-proxy-tor .
    
  
    # Exponer el puerto por defecto que usa la aplicación
    # El código Go usa 8443 por defecto, configurable con LISTEN_PORT.
    EXPOSE 8443
    
    # Establecer variables de entorno por defecto.
    # Estas pueden ser sobreescritas al ejecutar el contenedor (`docker run -e ...`)
    ENV LISTEN_PORT=8443
    ENV TOR_SOCKS_HOST=127.0.0.1   
    ENV TOR_SOCKS_PORT=9050
    ENV TLS_CERT_FILE=/app/server.crt 
    ENV TLS_KEY_FILE=/app/server.key   
    ENV PROXY_USER=
    ENV PROXY_PASSWORD=
    # Comando para ejecutar la aplicación cuando el contenedor inicie
    CMD ["./go-https-proxy-tor"]