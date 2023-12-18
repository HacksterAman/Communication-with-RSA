from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import socket

# Function to generate a pair of private and public keys
def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to serialize a public key to bytes
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

# Function to deserialize a public key from bytes
def deserialize_key(data):
    return serialization.load_pem_public_key(data, backend=default_backend())

# Main function to run the server
def main():
    # Generate server's private and public keys
    server_private_key, server_public_key = generate_key()

    # Create a socket for the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Bind the socket to an IP address and port
        server_socket.bind(("192.168.171.189", 12345))
        # Listen for incoming connections
        server_socket.listen()

        print("Server is listening for incoming connections...")

        # Accept a connection from a client
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connection from {addr}")

            # Send the server's public key to the client
            conn.sendall(serialize_key(server_public_key))

            # Receive the client's public key
            client_public_key_data = conn.recv(1024)
            client_public_key = deserialize_key(client_public_key_data)

            while True:
                # Receive and decrypt a message from the client
                encrypted_message = conn.recv(1024)
                decrypted_message = server_private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                print(f"Received from client: {decrypted_message.decode()}")

                # Encrypt and send a message to the client
                message = input("Server: ")
                encrypted_response = client_public_key.encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                conn.sendall(encrypted_response)

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
