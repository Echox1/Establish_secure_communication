import socket
import Public
import threading
#author: escape


# Define a unique separator for parsing messages
separator = "|||".encode('utf-8')

# Dictionaries to store certificates, public keys of other clients, and key fragments
client_certificates = {}
others_public_keys = {}
Key_frgments = {}

# Client identifiers
clientA = 'A'.encode('utf-8')
clientB = 'B'.encode('utf-8')
current_client = 'C'.encode('utf-8')

# Variable to store the combined session key
combinedKabc = b''

# Generate certificate, signature, and keys for client C
cert_pem, signature, private_key, public_key = Public.generate_cert('C')

def response_with_Kabc(sock):
    """Function to respond with the combined session key Kabc."""
    print("C sends response with Kabc")
    sock.sendall('send response to others'.encode('utf-8'))

    # Encrypt the session key with the public keys of A and B
    encrypted_Pass1 = Public.encrypt_data_with_aes(combinedKabc, Key_frgments['A'])
    encrypted_Pass2 = Public.encrypt_data_with_aes(combinedKabc, Key_frgments['B'])
    
    # Sign the encrypted data
    sign1 = Public.sign_data(private_key, encrypted_Pass1)
    sign2 = Public.sign_data(private_key, encrypted_Pass2)
    
    # Prepare the data for sending to server S
    response1 = clientA + separator + encrypted_Pass1 + separator + sign1
    response2 = clientB + separator + encrypted_Pass2 + separator + sign2
    Data_to_S = Public.encrypt_data(others_public_keys['S'], response1 + separator + response2)
    sign = Public.sign_data(private_key, Data_to_S)
    sock.sendall(sign + separator + Data_to_S)

    wait_for_response(sock)

def wait_for_response(sock):
    """Wait for a response from the server and process it."""
    count = 0
    while True:
        receive_data = sock.recv(4096)
        if receive_data != b'ACK':
            print("start to receive response")

            # Split the received data to extract the signature and the data
            parts = receive_data.split(separator)
            data = separator.join(parts[:-1])
            sign = parts[-1]

            # Verify the signature
            if Public.verify_signature(others_public_keys['S'], sign, data):
                client_name, encrypted_pass, sign = data.split(separator)
                decrypted_pass = Public.decrypt_data_with_aes(combinedKabc, encrypted_pass)
                client_name = client_name.decode('utf-8')

                # Verify the signature of the decrypted pass
                if Public.verify_signature(others_public_keys[client_name], sign, encrypted_pass):
                    if Key_frgments['C'] == decrypted_pass:
                        print(f"successfully receive {client_name}'s response from S")
                        count += 1
                        if count == 2:
                            print(f"Kabc from other clients is verified, now can communicate with Kabc")
                            break
                else:
                    print(f"verify {client_name}'s sign failed")
            else:
                print("verify S'sign failed ")

def send_pass_to_others(sock):
    """Send the key fragment to other clients via server S."""
    print("send PassC to S")
    sock.sendall('send key fragment to others'.encode('utf-8'))
    if sock.recv(1024) == b'ACK':
        # Generate and send PassC
        PassC = Public.generate_key_fragment()  # Placeholder for logic to generate PassC
        Key_frgments['C'] = PassC

        # Sign PassC and encrypt it for A and B
        sign = Public.sign_data(private_key, PassC)
        PassC_to_B = Public.encrypt_data(others_public_keys['B'], PassC + separator + sign)
        PassC_to_A = Public.encrypt_data(others_public_keys['A'], PassC + separator + sign)
        Data_to_S = Public.encrypt_data_20(others_public_keys['S'], clientB + separator + PassC_to_B + separator + clientA + separator + PassC_to_A)
        sign = Public.sign_data(private_key, Data_to_S)
        sock.sendall(sign + separator + Data_to_S)
        wait_for_pass(sock)

def wait_for_pass(sock):
    """Wait for key fragments from other clients through server S."""
    while True:
        receive_data = sock.recv(4096)
        if receive_data != b'ACK':
            parts = receive_data.split(separator)
            data = separator.join(parts[:-1])
            sign = parts[-1]

            # Verify the signature
            if Public.verify_signature(others_public_keys['S'], sign, data):
                client_name, encrypted_pass = data.split(separator)
                decrypted_pass = Public.decrypt_data(private_key, encrypted_pass)
                decrypted_pass, sign = decrypted_pass.split(separator)
                client_name = client_name.decode('utf-8')

                # Verify the signature on the decrypted pass
                if Public.verify_signature(others_public_keys[client_name], sign, decrypted_pass):
                    Key_frgments[client_name] = decrypted_pass
                    print(f"successfully receive {client_name}'s key fragment from S")
                else:
                    print(f"verify {client_name}'s sign failed")
            else:
                print("verify S'sign failed ")
            if len(Key_frgments) == 3:
                 global combinedKabc
                 combinedKabc = Public.combine_key_fragments(Key_frgments)   
                 break

def send_request_for_certificates(sock):
    """Request certificates for clients A and B from server S."""
    print("request CertA, CertB")
    sock.sendall('request certs from others'.encode('utf-8'))
    for i in range(2):
        received_data = sock.recv(4096)  # Receive data
        data, encrypted_symmetric_key = received_data.split(separator)
        symmetric_key = Public.decrypt_data(private_key, encrypted_symmetric_key)
        received_data = Public.decrypt_data_with_aes(symmetric_key, data)
        cert_pem, sign = received_data.split(separator)
        if Public.verify_signature(others_public_keys['S'], sign, cert_pem):
            client_name = Public.extract_username_from_cert(cert_pem)
            client_certificates[client_name] = cert_pem
            others_public_keys[client_name] = Public.extract_public_key(cert_pem)
            print(f"successfully receive {client_name}'s cert from S")
        else:
            print("verify signature from S failed")

def send_messages_to_server():
    """Main function to handle sending messages to the server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 12345))
        # Initially send the certificate and signature
        sock.sendall('C'.encode('utf-8'))

        # Wait for server acknowledgment
        ack = sock.recv(1024)
        if ack == b'ACK':
            sock.sendall(cert_pem + separator + signature)

        data = sock.recv(4096)
        if Public.Authentication(data):
            print("ChatServer Signature is valid.\r\n")
            cert = Public.Authentication(data)
            client_certificates['S'] = cert
            others_public_keys['S'] = Public.extract_public_key(cert)

            while True:
                print("\nSelect an option:")
                print("1. Request A and B's certificates and signatures from server S.")
                print("2. exchange key fragment through S.")
                print("3. response with Kabc.")
                print("4. communicate with Kabc.")

                choice = input("Enter your choice (1/2/3/4): ")

                if choice == '1':
                    send_request_for_certificates(sock)
                elif choice == '2':
                    send_pass_to_others(sock)
                elif choice == '3':
                    response_with_Kabc(sock)    
                elif choice == '4':
                    send_encrypted_messages(sock)
                else:
                    print("Invalid choice. Please try again.") 


def send_encrypted_messages(sock):
    """ This function sends an initial notification to other clients and then continuously accepts user input from the command
    line, encrypts the input using the AES encryption method, and sends it to the server. The
    server will then forward these encrypted messages to clients B and C."""
    # Send an initial message to notify other clients (handled by the server)
    sock.sendall('Encrypted message sent to others'.encode('utf-8'))
    # Start a thread to handle incoming messages
    threading.Thread(target=receive_messages, args=(sock,)).start()

    while True:
        # Get user input from the command line
        message = input("Enter message: ")
        # Encrypt the message using AES encryption with the session key
        encrypted_message = Public.encrypt_data_with_aes(combinedKabc, message.encode())
        # Send the encrypted message to the server, which will forward it to B and C
        sock.sendall(encrypted_message)
        print("Encrypted message sent to B and A.")

def receive_messages(sock):
    """Thread to handle receiving messages from other clients. This function continuously
    listens for messages from the server, which are forwarded from clients B or C, decrypts
    these messages using AES decryption, and displays them to the user."""
    while True:
        # Receive encrypted messages from the server, which are forwarded from B or C
        encrypted_message = sock.recv(1024)
        # Decrypt the message if it is not an 'ACK' notification
        if encrypted_message != b'ACK':
            decrypted_message = Public.decrypt_data_with_aes(combinedKabc, encrypted_message)
            # Display the decrypted message
            print(f"Received message: {decrypted_message.decode()}")
            # Prompt user to enter a new message
            print("Enter message: ", end="", flush=True)


send_messages_to_server()


