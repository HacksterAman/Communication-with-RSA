from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import socket


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_key(data):
    return serialization.load_pem_public_key(data, backend=default_backend())


def main():
    server_private_key, server_public_key = generate_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("localhost", 12345))
        server_socket.listen()

        print("Server is listening for incoming connections...")

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


if __name__ == "__main__":
    main()
