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
    """Read full responses from the GDB server."""
    response = b""
    while True:
        chunk = sock.recv(1024)
        response += chunk
        if chunk.endswith(b"#") or chunk.startswith(b"S") or chunk.startswith(b"T"):
            break
    return response.decode()

def gdb_connect(host, port):
    """Connect to the QEMU GDB server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def resolve_function_address(sock, function_name):
    """Resolve the address of a function using GDB RSP."""
    command = f"info address {function_name}"
    response = send_command(sock, command)
    print(f"Resolving address for {function_name}: {response}")
    # Parse the response to extract the address
    if "is at" in response:
        address = response.split("is at ")[-1].strip().split()[0]
        return address
    else:
        print(f"Could not resolve function: {function_name}")
        return None

def set_breakpoint(sock, address):
    """Set a breakpoint at the given address."""
    command = f"Z0,{address},1"  # 'Z0' sets a software breakpoint
    response = send_command(sock, command)
    if response.startswith("+"):
        print(f"Breakpoint set at address {address}")
    else:
        print(f"Failed to set breakpoint at address {address}: {response}")

def set_breakpoint_by_function(sock, function_name):
    """Set a breakpoint by function name."""
    address = resolve_function_address(sock, function_name)
    if address:
        set_breakpoint(sock, address)
    else:
        print(f"Could not set breakpoint for function: {function_name}")

def main():
    # Connect to QEMU GDB server
    host = "localhost"
    port = 1234
    sock = gdb_connect(host, port)
    print("Connected to GDB server")

    # Halt execution (optional, to ensure breakpoints can be set)
    send_command(sock, "Hc-1")  # Halt all threads
    print("Execution halted")

    # Example: Set breakpoints by function names
    functions = ["start_kernel", "do_fork", "sys_execve"]
    for function_name in functions:
        set_breakpoint_by_function(sock, function_name)

    # Resume execution
    send_command(sock, "c")  # 'c' is the continue command
    print("Execution continued")

    # Monitor execution for breakpoint hits
    try:
        while True:
            response = read_response(sock)
            if response.startswith("T") or response.startswith("S"):
                print(f"Breakpoint hit! Signal received: {response}")
                print("Logging breakpoint hit...")
                send_command(sock, "c")  # Continue execution
            else:
                print(f"Received unexpected response: {response}")
    except KeyboardInterrupt:
        print("Monitoring stopped.")

    # Close the socket
    sock.close()
    print("Disconnected from GDB server")

if __name__ == "__main__":
    main()
