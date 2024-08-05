import socket
import threading
import os
import Public
from threading import Lock

lock = Lock()
# Define a separator for message parsing
separator = "|||".encode('utf-8')

# Dictionaries to store client certificates, public keys, and socket connections
client_certificates = {}
others_public_keys = {}
all_connections = {}

# Lists to store pending responses and key fragments
Pass_store = []
response_store = []

# Generate server's own certificate and key pair
cert_pem, signature, private_key, public_key = Public.generate_cert('S')

server_name = 'S'.encode('utf-8')  # Identifier for the server


def Forward_messages(conn, current_client):
    conn.sendall(b'ACK')
    print("Start to forward messages")
    while True:
        message = conn.recv(4096)  # Receive message from sender
        for client_name, client_socket in all_connections.items():
            if client_name != current_client:
                client_socket.sendall(message)


def receive_response(conn, current_client):
    """Receive and process response from clients."""
    conn.sendall(b'ACK')
    lock.acquire()  # require for lock 

    recv_data = conn.recv(8192)
    sign, data = recv_data.split(separator)
    
    if Public.verify_signature(others_public_keys[current_client], sign, data):
        print(f"Receive Response from {current_client}\r\n")

        data = Public.decrypt_data(private_key, data)
        parts = data.split(separator)
        
        # Split and store data for forwarding
        if len(parts) == 6:
            segment1 = separator.join(parts[1:3])
            segment2 = separator.join(parts[4:6])
        client_name1, client_name2 = parts[0], parts[3]
        target_conn1, target_conn2 = all_connections[client_name1.decode('utf-8')], all_connections[client_name2.decode('utf-8')]
        
        current_client = current_client.encode('utf-8')

        # Reconstruct segments to send
        segment1, segment2 = current_client + separator + segment1, current_client + separator + segment2
        sign1, sign2 = Public.sign_data(private_key, segment1), Public.sign_data(private_key, segment2)
        
        # Store responses for future forwarding

        response_store.append((target_conn1, segment1 + separator + sign1))
        response_store.append((target_conn2, segment2 + separator + sign2))
        lock.release()

        Forward_response()
        

def Forward_response():
    """Forward responses to respective clients when all are ready."""
    if len(response_store) == 6:  # Ensure all responses are ready
        print("Start to forward response")
        for target_conn, data in response_store:
            target_conn.sendall(data)

            
    

    

def receive_keyFragment(conn, current_client):
    """Receive key fragments from clients and forward them appropriately."""
    conn.sendall(b'ACK')
    lock.acquire()   

    recv_data = conn.recv(8192)

    sign, data = recv_data.split(separator)
    
    if Public.verify_signature(others_public_keys[current_client], sign, data):
        print(f"Receive Pass from {current_client}\r\n")

        data = Public.decrypt_data(private_key, data)
        client_name1, Pass_to_user1, client_name2, Pass_to_user2 = data.split(separator)
        target_conn1, target_conn2 = all_connections[client_name1.decode('utf-8')], all_connections[client_name2.decode('utf-8')]
        current_client = current_client.encode('utf-8')
        # Prepare data for forwarding

        data1, data2 = current_client + separator + Pass_to_user1, current_client + separator + Pass_to_user2
        sign1, sign2 = Public.sign_data(private_key, data1), Public.sign_data(private_key, data2)
        Pass_store.append((target_conn1, data1 + separator + sign1))
        Pass_store.append((target_conn2, data2 + separator + sign2))
        lock.release()

        Forward_keyFragment()

def Forward_keyFragment():
    """Forward key fragments to respective clients when all are ready."""
    if len(Pass_store) == 6:  # Ensure all key fragments are ready
        for target_conn, data in Pass_store:
            target_conn.sendall(data)

def forward_certificates(conn, current_client):
    """Forward certificates to clients on request."""
    if len(client_certificates) == 3:  # Ensure all certificates are ready
        print(f"{current_client} is requesting other clients' certs\r\n")
        
        # Send certificates to the requesting client
        for client_name, cert_pem in client_certificates.items():
            if client_name != current_client:
                sign = Public.sign_data(private_key, cert_pem)  # Sign each certificate with server's private key
                symmetric_key = os.urandom(32)  # Generate a random symmetric key for encryption
                encrypted_data = Public.encrypt_data_with_aes(symmetric_key, cert_pem + separator + sign)  # Encrypt the certificate
                encrypted_symmetric_key = Public.encrypt_data(others_public_keys[current_client], symmetric_key)
                conn.sendall(encrypted_data + separator + encrypted_symmetric_key)

def handle_client(client_socket, client_name):
    """Handle each client connection."""
    all_connections[client_name] = client_socket  # Store client connection
    client_socket.sendall(b'ACK')
    
    data = client_socket.recv(4096)
    if Public.Authentication(data):
        print(f"Signature from {client_name} is valid.")
        cert = Public.Authentication(data)
        client_certificates[client_name] = cert
        others_public_keys[client_name] = Public.extract_public_key(cert)
        client_socket.sendall(cert_pem + separator + signature)
    else:
        print("Failed authentication.")

    # Respond to client requests
    while True:
        received = client_socket.recv(1024).decode('utf-8')
        if received == "request certs from others":
            forward_certificates(client_socket, client_name)
        elif received == "send key fragment to others":
            receive_keyFragment(client_socket, client_name)
        elif received == "send response to others":
            receive_response(client_socket, client_name)
        elif  received == "Encrypted message sent to others":
            Forward_messages(client_socket, client_name)

def start_server():
    """Start the server and listen for incoming connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)
    print("Server listening on port 12345")
    
    while True:
        conn, _ = server.accept()
        client_name = conn.recv(1024).decode('utf-8')
        threading.Thread(target=handle_client, args=(conn, client_name)).start()

if __name__ == '__main__':
    start_server()
