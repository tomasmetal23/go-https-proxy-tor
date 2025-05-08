# Go HTTPS Proxy & Reverse Proxy to Tor SOCKS

A Go application that listens for HTTPS connections and acts either as a standard **HTTPS Proxy** (tunneling traffic via Tor SOCKS5 with optional authentication) or as a **Reverse Proxy** to a backend web server, based on the incoming request method.

## Key Features:

*   **TLS Encryption:** Listens for incoming connections over TLS (HTTPS) on a configurable port (default: 8443).
*   **Dual Mode Operation:**
    *   **HTTPS Proxy:** Handles `CONNECT` requests according to the HTTP standard, establishing a tunnel to the requested target via a Tor SOCKS5 proxy.
    *   **Reverse Proxy:** Forwards all other HTTP methods (GET, POST, etc.) to a configurable backend web server (e.g., Caddy). This mode **does not** require proxy authentication.
*   **Basic Proxy Authentication:** Optionally requires username/password authentication (HTTP Basic Auth via `Proxy-Authorization` header) for **CONNECT requests only**. Configured via environment variables.
*   **Tor Integration:** Uses a configured Tor SOCKS5 proxy (default: `127.0.0.1:9050` or `host.containers.internal:9050` in container setups) for outbound `CONNECT` tunnels.
*   **External Certificates:** Requires valid TLS certificate (`.crt`) and private key (`.key`) files to be provided. Does not generate self-signed certificates.
*   **Configuration via Environment Variables:** Easily configure ports, proxy addresses, certificate paths, backend address, and authentication credentials.
*   **HTTP/1.1 Only:** Explicitly configured to only negotiate HTTP/1.1 with clients to ensure compatibility with the `CONNECT` method's hijacking requirement.

## Use Cases:

*   Providing secure, **authenticated** Tor-tunneled proxy access over a standard HTTPS proxy connection.
*   Serving a web application (via the reverse proxy backend) and providing an optionally authenticated Tor proxy service on the *same* port and IP address.
*   Simplifying access to Tor for clients that support standard HTTPS proxies with Basic Authentication.
*   Potentially bypassing network restrictions that block direct Tor access but allow HTTPS traffic.

**Example to bypass region ban in chatGPT website:**
![image](https://github.com/user-attachments/assets/82f30dc8-bbf4-4865-8062-d98b55de63fa)

![image](https://github.com/user-attachments/assets/4df7512a-9034-42a2-9fc5-72d5e835f022)

![image](https://github.com/user-attachments/assets/7f985212-dc27-488b-ac30-16e62125a920)

![image](https://github.com/user-attachments/assets/73f5738c-8364-4a18-bb7f-3389931b4241)
This configuration ensures that FoxyProxy only uses the Tor proxy for domains specified in the 'Proxy by Patterns' list.

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
*   `TLS_CERT_FILE`: Path to the TLS certificate file (Default: `/app/server.crt`). *Note: Default changed to `/app` for simpler Docker mounts, override if needed.*
*   `TLS_KEY_FILE`: Path to the TLS private key file (Default: `/app/server.key`). *Note: Default changed to `/app`.*
*   `CADDY_BACKEND_ADDR`: Full URL (including scheme `http://` or `https://`) of the backend web server for reverse proxying non-CONNECT requests (Default: `http://caddy:80`). Assumes a service named `caddy`.
*   **`PROXY_USER`**: (Optional) Username required for `CONNECT` requests. If this variable is **not set or is empty**, proxy authentication is **DISABLED**.
*   **`PROXY_PASSWORD`**: (Optional) Password required for `CONNECT` requests. Should be set if `PROXY_USER` is set.

## Usage:

### Running Directly:

1.  Set the required environment variables (including `PROXY_USER` and `PROXY_PASSWORD` if enabling authentication).
2.  Ensure Tor and the backend web server (if needed) are running.
3.  Place the certificate and key files in the configured paths.
4.  Build: `go build -o go-tls-tor-proxy .`
5.  Run: `./go-tls-tor-proxy`

### Running with Docker/Podman Compose (Recommended):

Refer to your `docker-compose.yml` or `podman-compose.yml`. Ensure:
*   The service builds from the Go source or uses a pre-built image.
*   Environment variables are set correctly, including `PROXY_USER` and `PROXY_PASSWORD` if needed. Reference other services (like `tor`, `caddy`) by their service names.
*   Volumes are mounted for the TLS certificate and key files.
*   The `LISTEN_PORT` is exposed.
*   It depends on the `tor` service (and `caddy` service if used).

## Client Setup:

Configure your client application to use a standard **HTTPS Proxy**.

*   **Proxy Type:** HTTPS
*   **Server/Host:** The domain name or IP address where this Go application is running (e.g., `tor.saiyans.com.ve`).
*   **Port:** The `LISTEN_PORT` configured for this application (e.g., `8443`).
*   **Authentication:**
    *   If `PROXY_USER` **is set** on the server: Enable Basic Authentication in the client and provide the configured **Username** and **Password**.
    *   If `PROXY_USER` **is not set** on the server: Disable authentication in the client.

### Tested Clients:

*   **Browser:** FoxyProxy Standard (Browser Extension) - Works well. Supports adding username/password for the HTTPS proxy entry.
*   **Android:** Drony - Appears to work correctly. Supports setting username/password for the HTTPS proxy. Other clients might exhibit issues, potentially related to latency handling or specific connection types.
*   **Command Line:** `curl` - Works well. Use `-x https://<host>:<port>` and `--proxy-user "<username>:<password>"`.

## How it Works:

1.  The server listens for TLS connections on the specified port.
2.  Upon receiving a new connection, the standard Go `net/http` server handles the initial request.
3.  **If the request method is `CONNECT`:**
    *   **Authentication Check:** If `PROXY_USER` is configured, the server checks the `Proxy-Authorization` header for valid Basic Authentication credentials. If invalid or missing, it responds with `407 Proxy Authentication Required` and closes the connection.
    *   **Connection Establishment:** If authentication succeeds (or is disabled), the server attempts to establish a TCP connection to the requested target host/port via the configured Tor SOCKS5 proxy.
    *   **Hijacking:** If the SOCKS connection is successful, it hijacks the client's underlying TLS connection.
    *   **Confirmation:** It sends `HTTP/1.1 200 Connection established` back to the client.
    *   **Tunneling:** It then blindly relays TCP data between the client and the connection established through Tor.
    *   Handles SOCKS connection errors by returning appropriate HTTP error codes (502 Bad Gateway, 504 Gateway Timeout) to the client *before* hijacking (if possible).
4.  **If the request method is anything else (GET, POST, etc.):**
    *   The request is passed **without proxy authentication** to the `httputil.ReverseProxy`.
    *   The reverse proxy forwards the request to the configured `CADDY_BACKEND_ADDR`.
    *   The response from the backend server is streamed back to the original client.

## Contribution:

Contributions, ideas, and feedback are welcome! If you are interested in helping to develop this project, please feel free to fork the repository and submit pull requests.
