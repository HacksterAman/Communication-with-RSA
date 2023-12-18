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
    client_private_key, client_public_key = generate_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(("localhost", 12345))

        # Receive the server's public key
        server_public_key_data = client_socket.recv(1024)
        server_public_key = deserialize_key(server_public_key_data)

        # Send the client's public key to the server
        client_socket.sendall(serialize_key(client_public_key))

        while True:
            # Encrypt and send a message to the server
            message = input("Client: ")
            encrypted_response = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            client_socket.sendall(encrypted_response)

            # Receive and decrypt a message from the server
            encrypted_message = client_socket.recv(1024)
            decrypted_message = client_private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            print(f"Received from server: {decrypted_message.decode()}")


if __name__ == "__main__":
    main()
