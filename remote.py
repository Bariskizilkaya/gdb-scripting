import socket

def calculate_checksum(command):
    """Calculate checksum for the GDB packet."""
    return f"{sum(ord(c) for c in command) % 256:02x}"

def send_command(sock, command):
    """Send a command to the GDB server and get the response."""
    packet = f"${command}#{calculate_checksum(command)}"
    sock.sendall(packet.encode())
    response = b""
    while True:
        chunk = sock.recv(1024)
        response += chunk
        if b"+" in chunk or b"-" in chunk:  # Acknowledgment
            break
    return response.decode()

def read_response(sock):
    """Read responses from the GDB server continuously."""
    response = b""
    while True:
        chunk = sock.recv(1024)
        response += chunk
        # Break on end of packet (e.g., newlines or signals like TXX or SXX)
        if chunk.endswith(b"#") or chunk.startswith(b"S") or chunk.startswith(b"T"):
            break
    return response.decode()

def gdb_connect(host, port):
    """Connect to the QEMU GDB server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def set_breakpoint(sock, address):
    """Set a breakpoint at the given address."""
    command = f"Z0,{address},1"  # 'Z0' sets a software breakpoint
    response = send_command(sock, command)
    if response.startswith("+"):
        print(f"Breakpoint set at address {address}")
    else:
        print(f"Failed to set breakpoint at address {address}: {response}")

def monitor_execution(sock):
    """Monitor execution and log messages on breakpoint hits."""
    print("Monitoring execution. Waiting for breakpoints to hit...")
    while True:
        response = read_response(sock)
        if response.startswith("T") or response.startswith("S"):
            print(f"Breakpoint hit! Signal received: {response}")
            # Example log message; customize as needed
            print("Breakpoint event detected. Continuing execution...")
            send_command(sock, "c")  # Continue execution
        else:
            print(f"Received unexpected response: {response}")

def main():
    # Connect to QEMU GDB server
    host = "localhost"
    port = 1234
    sock = gdb_connect(host, port)
    print("Connected to GDB server")

    # Halt execution (optional, to ensure breakpoints can be set)
    send_command(sock, "Hc-1")  # Halt all threads
    print("Execution halted")

    # Example: Set breakpoints
    set_breakpoint(sock, "0xFFFFFFFF81000000")  # Replace with actual address
    set_breakpoint(sock, "0xFFFFFFFF81000100")  # Replace with actual address

    # Resume execution
    send_command(sock, "c")  # 'c' is the continue command
    print("Execution continued")

    # Monitor execution for breakpoint hits
    try:
        monitor_execution(sock)
    except KeyboardInterrupt:
        print("Monitoring stopped.")

    # Close the socket
    sock.close()
    print("Disconnected from GDB server")

if __name__ == "__main__":
    main()
