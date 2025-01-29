import socket

def calculate_checksum(data):
    """Calculate RSP checksum."""
    checksum = sum(ord(char) for char in data) % 256
    return f"{checksum:02x}"

def send_packet(sock, payload):
    """Send RSP packet."""
    checksum = calculate_checksum(payload)
    packet = f"${payload}#{checksum}"
    sock.sendall(packet.encode())
    print(f"Sent: {packet}")

def receive_response(sock):
    """Receive response from GDB server."""
    response = sock.recv(4096).decode()
    print(f"Received: {response}")
    return response

def main():
    # Connect to the GDB server (update host and port as needed)
    gdb_host = '127.0.0.1'  # Localhost
    gdb_port = 1234         # Default GDB server port in QEMU

    try:
        # Establish connection to the GDB server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((gdb_host, gdb_port))
            print("Connected to GDB server.")

            custom_command = "B,some_data"  # Replace 'some_data' with actual payload
            send_packet(sock, custom_command)
            receive_response(sock)

            custom_command = "c"  # Replace 'some_data' with actual payload
            send_packet(sock, custom_command)
            # Receive and print the server's response


    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
