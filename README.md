# Go HTTPS Proxy & Reverse Proxy to Tor SOCKS

A Go application that listens for HTTPS connections and acts either as a standard **HTTPS Proxy** (tunneling traffic via Tor SOCKS5) or as a **Reverse Proxy** to a backend web server, based on the incoming request method.

## Key Features:

*   **TLS Encryption:** Listens for incoming connections over TLS (HTTPS) on a configurable port (default: 8443).
*   **Dual Mode Operation:**
    *   **HTTPS Proxy:** Handles `CONNECT` requests according to the HTTP standard, establishing a tunnel to the requested target via a Tor SOCKS5 proxy.
    *   **Reverse Proxy:** Forwards all other HTTP methods (GET, POST, etc.) to a configurable backend web server (e.g., Caddy).
*   **Tor Integration:** Uses a configured Tor SOCKS5 proxy (default: `127.0.0.1:9050` or `host.containers.internal:9050` in container setups) for outbound `CONNECT` tunnels.
*   **External Certificates:** Requires valid TLS certificate (`.crt`) and private key (`.key`) files to be provided. Does not generate self-signed certificates.
*   **Configuration via Environment Variables:** Easily configure ports, proxy addresses, certificate paths, and the backend address.
*   **HTTP/1.1 Only:** Explicitly configured to only negotiate HTTP/1.1 with clients to ensure compatibility with the `CONNECT` method's hijacking requirement.

## Use Cases:

*   Providing Tor-tunneled proxy access securely over a standard HTTPS proxy connection.
*   Serving a web application (via the reverse proxy backend) and providing a Tor proxy service on the *same* port and IP address.
*   Simplifying access to Tor for clients that support standard HTTPS proxies.
*   Potentially bypassing network restrictions that block direct Tor access but allow HTTPS traffic.

## Requirements:

*   Go (tested with 1.18+, likely works with newer versions) for building/running directly.
*   A running Tor instance with the SOCKS5 proxy interface enabled.
*   Valid TLS certificate and key files (`server.crt`, `server.key`).
*   A backend web server (like Caddy, Nginx, Apache) running and accessible if you intend to use the reverse proxy functionality for non-CONNECT requests.
*   (Optional) Docker / Podman and Docker Compose / Podman Compose for containerized deployment.

## Configuration:

The application is configured using environment variables:

*   `LISTEN_PORT`: The port number for the HTTPS listener (Default: `8443`).
*   `TOR_SOCKS_HOST`: The hostname or IP address of the Tor SOCKS5 proxy (Default: `127.0.0.1`). Use `host.containers.internal` or the service name (e.g., `tor`) in Docker/Podman setups.
*   `TOR_SOCKS_PORT`: The port of the Tor SOCKS5 proxy (Default: `9050`).
*   `TLS_CERT_FILE`: Path to the TLS certificate file (Default: `/etc/ssl/certs/server.crt`).
*   `TLS_KEY_FILE`: Path to the TLS private key file (Default: `/etc/ssl/private/server.key`).
*   `CADDY_BACKEND_ADDR`: Full URL (including scheme `http://` or `https://`) of the backend web server for reverse proxying (Default: `http://localhost:80`). Use the service name (e.g., `http://caddy:80`) in Docker/Podman setups.

## Usage:

### Running Directly:

1.  Set the required environment variables.
2.  Ensure Tor and the backend web server (if needed) are running.
3.  Place the certificate and key files in the configured paths.
4.  Build: `go build -o go-tls-tor-proxy .`
5.  Run: `./go-tls-tor-proxy`

### Running with Docker/Podman Compose (Recommended):

Refer to your `docker-compose.yml` or `podman-compose.yml`. Ensure:
*   The service builds from the Go source or uses a pre-built image.
*   Environment variables are set correctly, referencing other services (like `tor`, `caddy`) by their service names.
*   Volumes are mounted for the TLS certificate and key files.
*   The `LISTEN_PORT` is exposed.
*   It depends on the `tor` service (and `caddy` service if used).

## Client Setup:

Configure your client application to use a standard **HTTPS Proxy**.

*   **Proxy Type:** HTTPS
*   **Server/Host:** The domain name or IP address where this Go application is running (e.g., `tor.saiyans.com.ve`).
*   **Port:** The `LISTEN_PORT` configured for this application (e.g., `8443`).
*   **Authentication:** None (currently not implemented).

### Tested Clients:

*   **Browser:** FoxyProxy Standard (Browser Extension) - Works well. Configure a new HTTPS proxy entry.
*   **Android:** Drony - Appears to work correctly when configured as an HTTPS proxy. Other clients like V2RayNG or Proxifier might exhibit issues (like frequent connection drops or errors on non-HTTP ports) likely due to their handling of latency or specific connection types, not necessarily a fault of this proxy server.
*   **Command Line:** `curl` - Works well using the `-x https://<host>:<port>` flag.

## How it Works:

1.  The server listens for TLS connections on the specified port.
2.  Upon receiving a new connection, the standard Go `net/http` server handles the initial request.
3.  **If the request method is `CONNECT`:**
    *   The custom handler attempts to establish a TCP connection to the requested target host/port via the configured Tor SOCKS5 proxy.
    *   If successful, it hijacks the client's underlying TLS connection.
    *   It sends `HTTP/1.1 200 Connection established` back to the client.
    *   It then blindly relays TCP data between the client and the connection established through Tor.
    *   Handles SOCKS connection errors by returning appropriate HTTP error codes (502 Bad Gateway, 504 Gateway Timeout) to the client *before* hijacking.
4.  **If the request method is anything else (GET, POST, etc.):**
    *   The request (including headers like `X-Forwarded-For`) is passed to the `httputil.ReverseProxy`.
    *   The reverse proxy forwards the request to the configured `CADDY_BACKEND_ADDR`.
    *   The response from the backend server is streamed back to the original client.

## Contribution:

Contributions, ideas, and feedback are welcome! If you are interested in helping to develop this project, please feel free to fork the repository and submit pull requests.