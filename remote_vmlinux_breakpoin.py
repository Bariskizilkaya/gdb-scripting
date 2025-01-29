import socket
import subprocess
import sys
import re

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
        if chunk.endswith(b"#") or chunk.startswith(b"T") or chunk.startswith(b"S"):
            break
    return response.decode()

def gdb_connect(host, port):
    """Connect to the QEMU GDB server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def resolve_function_address_vmlinux(vmlinux_path, function_name):
    """Resolve function address using vmlinux symbol table."""
    try:
        result = subprocess.run(
            ["nm", vmlinux_path],
            text=True,
            capture_output=True,
            check=True
        )
        for line in result.stdout.splitlines():
            if f" T {function_name}" in line:
                address = line.split()[0]
                print(f"Resolved {function_name} to address {address} using vmlinux")
                return address
        print(f"Function {function_name} not found in vmlinux")
        return None
    except Exception as e:
        print(f"Error resolving address from vmlinux: {e}")
        return None

def resolve_function_address(sock, function_name):
    """Resolve the address of a function using GDB RSP."""
    command = f"info address {function_name}"
    response = send_command(sock, command)
    print(f"Resolving address for {function_name}: {response}")
    if "is at" in response:
        address = response.split("is at ")[-1].strip().split()[0]
        return address
    else:
        print(f"Could not resolve function: {function_name}")
        return None

def set_hardware_breakpoint(sock, address):
    """Set a hardware breakpoint at the given address."""
    if not address.startswith("0x"):  # Ensure the address is in hexadecimal format
        address = f"0x{address}"
    command = f"Z1,{address},1"  # 'Z1' sets a hardware breakpoint
    response = send_command(sock, command)
    print(f"Command sent: {command}")
    print(f"Response received: {response}")
    if response.startswith("+"):
        print(f"Hardware breakpoint set at address {address}")
    else:
        print(f"Failed to set hardware breakpoint at address {address}: {response}")
        # Try software breakpoint as a fallback
        print("Attempting to set software breakpoint...")
        command = f"Z0,{address},1"  # 'Z0' sets a software breakpoint
        response = send_command(sock, command)
        print(f"Response received for software breakpoint: {response}")
        if response.startswith("+"):
            print(f"Software breakpoint set at address {address}")
        else:
            print(f"Failed to set software breakpoint at address {address}: {response}")

def set_end_of_function_breakpoint(sock, function_name):
    """Set a breakpoint at the end of the function (near the return instruction)."""
    command = f"disas {function_name}"
    response = send_command(sock, command)
    print(f"Disassembling function {function_name}: {response}")
    # Look for a 'ret' instruction in the disassembly (end of the function)
    match = re.search(r"(\s+ret\s+.*?)([0-9a-fA-F]+)", response)
    if match:
        ret_address = match.group(2)  # Capture the address of the return instruction
        print(f"Found return instruction for {function_name} at address {ret_address}")
        set_hardware_breakpoint(sock, ret_address)
    else:
        print(f"Could not find return instruction for function {function_name}")

def set_hardware_breakpoint_by_function(sock, function_name, vmlinux_path=None):
    """Set hardware breakpoints at the start and end of a function."""
    address = None
    if vmlinux_path:
        address = resolve_function_address_vmlinux(vmlinux_path, function_name)
    if not address:  # Fall back to GDB if vmlinux resolution fails
        address = resolve_function_address(sock, function_name)
    if address:
        set_hardware_breakpoint(sock, address)
        set_end_of_function_breakpoint(sock, function_name)
    else:
        print(f"Could not set hardware breakpoint for function: {function_name}")

def handle_breakpoint_hit(response):
    """Handle the GDB server's response to a breakpoint hit."""
    if response.startswith("T"):
        # Extract the address from the response
        match = re.search(r"T(\w+)", response)
        if match:
            address = match.group(1)
            print(f"Breakpoint hit at address: {address}")
        else:
            print(f"Breakpoint hit, but could not extract address: {response}")
    elif response.startswith("S"):
        print(f"Signal received from GDB server: {response}")
    else:
        print(f"Unexpected response during breakpoint monitoring: {response}")

def main():
    # Connect to QEMU GDB server
    host = "localhost"
    port = 1234
    vmlinux_path = "/home/asd/Documents/fuzzer/experimentQEMU/linux/vmlinux"
    sock = gdb_connect(host, port)
    print("Connected to GDB server")

    # Halt execution to ensure breakpoints can be set
    send_command(sock, "Hc-1")  # Halt all threads
    print("Execution halted")

    # Example: Set hardware breakpoints by function names
    functions = sys.argv[1:] if len(sys.argv) > 1 else ["start_kernel", "kmalloc"]
    for function_name in functions:
        set_hardware_breakpoint_by_function(sock, function_name, vmlinux_path)

    # Resume execution
    send_command(sock, "c")  # 'c' is the continue command
    print("Execution continued")
    
    # Monitor execution for breakpoint hits
    try:
        while True:
            response = read_response(sock)
            print(response)
            if response.startswith("T") or response.startswith("S"):
                handle_breakpoint_hit(response)
                send_command(sock, "c")  # Continue execution after logging
            else:
                print(f"Received unexpected response: {response}")
    except KeyboardInterrupt:
        print("Monitoring stopped.")
    finally:
        sock.close()
        print("Disconnected from GDB server")

if __name__ == "__main__":
    main()
