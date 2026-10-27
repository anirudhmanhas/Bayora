import asyncio
import logging
import os
import sys

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] [egress-proxy] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("egress-proxy")

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("PROXY_PORT", "3128"))
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.getenv("ALLOWED_HOSTS", "api.groq.com").split(",")
    if h.strip()
}
ALLOWED_PORTS = {
    int(p.strip())
    for p in os.getenv("ALLOWED_PORTS", "443").split(",")
    if p.strip()
}


async def pipe_streams(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        logger.debug(f"Pipe stream error: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    client_ip, client_port = client_writer.get_extra_info("peername", ("unknown", 0))

    try:
        # Read the initial request line (up to 8KB)
        raw_header = await client_reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionResetError):
        client_writer.close()
        return
    except Exception as exc:
        logger.debug(f"Read error from {client_ip}:{client_port}: {exc}")
        client_writer.close()
        return

    lines = raw_header.decode("latin1", errors="replace").split("\r\n")
    if not lines or not lines[0].strip():
        client_writer.close()
        return

    req_line = lines[0].strip().split()
    if len(req_line) < 2:
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        return

    method = req_line[0].upper()
    target = req_line[1]

    # Health check probe support on same port
    if method in ("GET", "HEAD") and target in ("/health", "/healthz", "/"):
        body = b'{"status":"ok","service":"egress-proxy","allowed_hosts":["api.groq.com"]}\n'
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        client_writer.write(resp)
        await client_writer.drain()
        client_writer.close()
        return

    if method != "CONNECT":
        # Deny direct cleartext HTTP forwarding - only strict CONNECT tunnels permitted
        logger.warning(f"Blocked non-CONNECT method {method} from {client_ip}:{client_port}")
        client_writer.write(
            b"HTTP/1.1 405 Method Not Allowed\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n\r\n"
            b"Only CONNECT tunneling is permitted through this proxy.\n"
        )
        await client_writer.drain()
        client_writer.close()
        return

    # Parse host and port from CONNECT target (e.g., "api.groq.com:443")
    host, _, port_str = target.partition(":")
    try:
        port = int(port_str) if port_str else 443
    except ValueError:
        port = -1

    host_normalized = host.strip().lower()

    # Strict allowlist check: host must match ALLOWED_HOSTS and port must match ALLOWED_PORTS
    if host_normalized not in ALLOWED_HOSTS or port not in ALLOWED_PORTS:
        logger.warning(
            f"Blocked egress to {host_normalized}:{port} from {client_ip}:{client_port} (Not in allowlist)"
        )
        client_writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n\r\n"
            b"Egress blocked: Destination host is not authorized by egress policy.\n"
        )
        await client_writer.drain()
        client_writer.close()
        return

    # Connect to target
    logger.info(f"Allowing egress tunnel to {host_normalized}:{port} from {client_ip}:{client_port}")
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(host_normalized, port),
            timeout=10.0,
        )
    except Exception as exc:
        logger.error(f"Failed to connect to upstream {host_normalized}:{port}: {exc}")
        client_writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n\r\n"
            b"Failed to connect to upstream host.\n"
        )
        await client_writer.drain()
        client_writer.close()
        return

    # Acknowledge connection established
    client_writer.write(
        b"HTTP/1.1 200 Connection Established\r\n"
        b"Proxy-Agent: Bayora-Egress-Proxy\r\n\r\n"
    )
    await client_writer.drain()

    # Tunnel bytes bidirectionally
    await asyncio.gather(
        pipe_streams(client_reader, remote_writer),
        pipe_streams(remote_reader, client_writer),
        return_exceptions=True,
    )


async def main():
    logger.info(
        f"Starting Bayora Egress Proxy on {LISTEN_HOST}:{LISTEN_PORT} "
        f"(Allowed hosts: {sorted(list(ALLOWED_HOSTS))}, Allowed ports: {sorted(list(ALLOWED_PORTS))})"
    )
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down egress proxy.")
