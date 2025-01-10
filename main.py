import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


def server():
    # Генерація пари RSA-ключів
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Серіалізація публічного ключа для відправки клієнту
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Налаштування серверного сокету
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 9999))
    server_socket.listen(1)
    print("Server is listening on port 9999...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    # Отримання привітання від клієнта
    client_hello = conn.recv(1024)
    print(f"Received from client: {client_hello.decode()}")

    # Відправка привітання від сервера та публічного ключа
    server_hello = b"Hello from server"
    conn.send(server_hello + b"\n" + public_key_bytes)

    # Отримання зашифрованого премастер-секрету
    encrypted_premaster = conn.recv(256)
    premaster_secret = private_key.decrypt(
        encrypted_premaster,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Decrypted premaster secret: {premaster_secret}")

    # Генерація сеансового ключа за допомогою премастер-секрету
    salt = b"random_salt"  # Повинно бути унікальним та безпечно передаватися
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    session_key = kdf.derive(premaster_secret)

    print(f"Generated session key: {session_key.hex()}")

    # Очікування повідомлення "готовності" від клієнта
    encrypted_ready = conn.recv(1024)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(b"16byteslongivvvv"), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_ready = decryptor.update(encrypted_ready) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    ready_message = unpadder.update(padded_ready) + unpadder.finalize()

    print(f"Received decrypted message: {ready_message.decode()}")

    # Відправка зашифрованого "готового" повідомлення клієнту
    message = b"Server ready"
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    conn.send(encrypted_message)

    print("Handshake complete. Communication secured.")

    # Отримання додаткового повідомлення від клієнта
    encrypted_client_message = conn.recv(1024)
    decryptor = cipher.decryptor()
    padded_client_message = decryptor.update(encrypted_client_message) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    client_message = unpadder.update(padded_client_message) + unpadder.finalize()
    print(f"Decrypted message from client: {client_message.decode()}")

    # Відправка відповіді клієнту
    server_response = b"I am fine, thank you!"
    padder = sym_padding.PKCS7(128).padder()
    padded_response = padder.update(server_response) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_response = encryptor.update(padded_response) + encryptor.finalize()
    conn.send(encrypted_response)

    conn.close()
    server_socket.close()


def client():
    # Підключення до сервера
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 9999))

    # Відправка привітання від клієнта
    client_hello = b"Hello from client"
    client_socket.send(client_hello)

    # Отримання привітання від сервера та публічного ключа
    response = client_socket.recv(2048)
    server_hello, public_key_bytes = response.split(b"\n", 1)
    print(f"Received from server: {server_hello.decode()}")

    # Десеріалізація публічного ключа сервера
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    print("Received public key:")
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    # Генерація премастер-секрету
    premaster_secret = os.urandom(16)
    print(f"Generated premaster secret: {premaster_secret}")

    # Шифрування премастер-секрету публічним ключем сервера
    encrypted_premaster = public_key.encrypt(
        premaster_secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(encrypted_premaster)

    # Генерація сеансового ключа за допомогою премастер-секрету
    salt = b"random_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    session_key = kdf.derive(premaster_secret)
    print(f"Generated session key: {session_key.hex()}")

    # Відправка повідомлення "готовності"
    message = b"Client ready"
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(b"16byteslongivvvv"), backend=default_backend())
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    client_socket.send(encrypted_message)

    # Отримання зашифрованого "готового" повідомлення від сервера
    encrypted_response = client_socket.recv(1024)
    decryptor = cipher.decryptor()
    padded_response = decryptor.update(encrypted_response) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    response_message = unpadder.update(padded_response) + unpadder.finalize()
    print(f"Decrypted message from server: {response_message.decode()}")

    print("Handshake complete. Communication secured.")

    # Відправка додаткового повідомлення серверу
    client_message = b"How are you?"
    padder = sym_padding.PKCS7(128).padder()
    padded_client_message = padder.update(client_message) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_client_message = encryptor.update(padded_client_message) + encryptor.finalize()
    client_socket.send(encrypted_client_message)

    # Отримання відповіді від сервера
    encrypted_server_response = client_socket.recv(1024)
    decryptor = cipher.decryptor()
    padded_server_response = decryptor.update(encrypted_server_response) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    server_response = unpadder.update(padded_server_response) + unpadder.finalize()
    print(f"Decrypted response from server: {server_response.decode()}")

    client_socket.close()


if __name__ == "__main__":
    from multiprocessing import Process

    # Створення окремих процесів для сервера та клієнта
    server_process = Process(target=server)
    client_process = Process(target=client)

    server_process.start()
    client_process.start()

    server_process.join()
    client_process.join()
