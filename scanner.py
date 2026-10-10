import asyncio

async def scan_single_port(target_host: str, port: int) -> dict:
    """
    Scans a single TCP port asynchronously and attempts to perform Banner Grabbing.

    Args:
        target_host (str): The target IP address or Domain name to scan.
        port (int): The specific port number to probe (1-65535).

    Returns:
        dict: A dictionary containing the target port, its active network status 
              ('open' or 'closed'), and the retrieved service banner if successful.
    """
    try:
        # Attempt to establish a raw TCP connection with a strict 1.0-second timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, port), 
            timeout=1.0
        )

        banner = "Unknown Service (No banner returned)"
        try:
            # Send a generic probe (useful for web/HTTP servers) to trigger a response banner
            writer.write(b"HEAD / HTTP/1.1\r\n\r\n")
            await writer.drain()

            # Read up to 1024 bytes of the response banner from the service
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            if data:
                # Decode, grab the first line, and strip trailing whitespaces safely
                banner = data.decode('utf-8', errors='ignore').split('\r\n')[0].strip()
        except Exception:
            # Connection succeeded, but the service did not respond or timed out during read
            pass
        finally:
            # Gracefully close the socket connection
            writer.close()
            await writer.wait_closed()

        return {"port": port, "status": "open", "banner": banner}

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # Port is closed, filtered, or the connection request was rejected
        return {"port": port, "status": "closed", "banner": None}

async def run_port_scan(target_host: str, ports: list) -> list:
    """
    Orchestrates the asynchronous network scan across multiple target ports.

    Args:
        target_host (str): The target IP address or Domain name for the operation.
        ports (list): A list of target port numbers (integers) scheduled to be scanned.

    Returns:
        list: A filtered list of dictionaries containing only the discovered open ports.
    """
    # Create an asynchronous task for every port in the range
    tasks = [scan_single_port(target_host, port) for port in ports]

    # Execute all tasks concurrently and wait for them to finish
    results = await asyncio.gather(*tasks)

    # Filter the results: return only the assets that are explicitly marked 'open'
    open_ports = [res for res in results if res["status"] == "open"]
    return open_ports
