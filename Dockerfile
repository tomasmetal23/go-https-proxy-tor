# Etapa de construcción
FROM golang:1.22-alpine AS builder

# Instalar dependencias de COMPILACIÓN (solo necesarias para builder)
RUN apk add --no-cache \
    gcc \
    musl-dev \
    openssl-dev  # Necesario si usas CGO con crypto/tls

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Compilar con soporte para TLS
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o /app/gotls-tor-bridge

# Etapa final (imagen mínima)
FROM alpine:3.19

# Instalar SOLO lo necesario para RUNTIME
RUN apk add --no-cache \
    ca-certificates \  # Para verificar certificados TLS remotos
    libssl3 \         # Soporte criptográfico para crypto/tls
    tzdata            # Zonas horarias (opcional, útil para logs)

WORKDIR /app
COPY --from=builder /app/gotls-tor-bridge .


EXPOSE 443
CMD ["./gotls-tor-bridge"]