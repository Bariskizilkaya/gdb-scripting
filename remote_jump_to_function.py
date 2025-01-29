import socket
import subprocess

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
    # Remove the leading '$' before returning the response
    return response.decode().lstrip('$')

def read_response(sock):
    """Read full responses from the GDB server."""
    response = b""
    while True:
        chunk = sock.recv(1024)
        response += chunk
        if b"T" in chunk or b"S" in chunk or b"#" in chunk:
            break
    # Remove the leading '$' before returning the response
    return response.decode().lstrip('$')

def gdb_connect(host, port):
    """Connect to the QEMU GDB server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def resolve_function_address_vmlinux(vmlinux_path, function_name):
    """Resolve function address from vmlinux using 'nm'."""
    try:
        result = subprocess.run(["nm", vmlinux_path], text=True, capture_output=True, check=True)
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

def set_breakpoint(sock, address):
    """Set a hardware breakpoint at the given address."""
    command = f"Z1,{address},1"  # 'Z1' sets a hardware breakpoint
    response = send_command(sock, command)
    if response.startswith("+"):
        print(f"Hardware breakpoint set at address {address}")
    else:
        print(f"Failed to set breakpoint at address {address}: {response}")

def read_register(sock, register):
    """Read the value of a register."""
    command = f"p ${register}"
    response = send_command(sock, command)
    print(f"Register {register} value: {response}")
    return response.split("=")[-1].strip()

def write_register(sock, register, value):
    """Write a value to a register."""
    command = f"p ${register}={value}"
    response = send_command(sock, command)
    print(f"Set register {register} to {value}: {response}")

def handle_signal_response(sock, response):
    """Handle GDB server's signal response (e.g., breakpoint hit)."""
    if response.startswith("T05"):
        print(f"Breakpoint hit! Signal received: {response}")
        # Parse thread info (e.g., 'thread:01')
        thread_info = response.split("thread:")[-1].split(";")[0]
        print(f"Thread ID: {thread_info}")

        # Inspect the instruction pointer (e.g., 'rip' for x86_64)
        ip_value = read_register(sock, "rip")  # Change to 'pc' for ARM
        print(f"Instruction pointer (IP) after breakpoint: {ip_value}")

        # Resume execution after breakpoint hit
        send_command(sock, "c")
        print("Resumed execution after breakpoint.")
    else:
        print(f"Unexpected response: {response}")

def jump_to_function(sock, address, args):
    """Run the function at the given address with arguments."""
    # Set up arguments in registers
    for i, arg in enumerate(args):
        if i < 6:  # For x86_64, first 6 args go into rdi, rsi, rdx, rcx, r8, r9
            reg = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][i]
            write_register(sock, reg, arg)
        else:
            print(f"Warning: Argument {arg} beyond 6th is not handled in this example.")
    
    # Set the program counter (PC) to the function's address
    write_register(sock, "rip", address)  # For x86_64, use "pc" for ARM
    print(f"Program counter (PC) set to {address}")

def main():
    """Main function to connect to GDB server, set breakpoints, and handle execution."""
    # Connect to QEMU GDB server
    host = "localhost"
    port = 1234
    vmlinux_path = "/home/asd/Documents/fuzzer/experimentQEMU/linux/vmlinux"
    sock = gdb_connect(host, port)
    print("Connected to GDB server")

    # Halt execution
    send_command(sock, "Hc-1")
    print("Execution halted")

    # Resolve the function address
    function_name = "do_msgsnd"  # Replace with the function you want to break on
    function_address = resolve_function_address_vmlinux(vmlinux_path, function_name)
    if not function_address:
        print(f"Could not resolve address for {function_name}")
        return

    # Set a hardware breakpoint at the function address
    set_breakpoint(sock, function_address)

    # Continue execution
    send_command(sock, "c")
    print("Execution continued")

    # Wait for the breakpoint to be hit and handle signal
    while True:
        response = read_response(sock)
        if response.startswith("T"):
            handle_signal_response(sock, response)
        elif response.startswith("S"):
            print("Thread stopped. Proceeding...")
            send_command(sock, "c")
        else:
            print(f"Unexpected response: {response}")

if __name__ == "__main__":
    main()
