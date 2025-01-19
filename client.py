# ИСАДИЧЕВА Д.А., ДПИ22-1

import socket
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Конфигурация клиента
SERVER_HOST = '127.0.0.1'  # IP-адрес сервера
SERVER_PORT = 8080         # Порт, который слушает сервер
CLIENT_PRIVATE_KEY_FILE = "client_private.pem"  # Файл для хранения приватного ключа клиента
CLIENT_PUBLIC_KEY_FILE = "client_public.pem"    # Файл для хранения публичного ключа клиента

# Генерация или загрузка ключей RSA для клиента
if not os.path.exists(CLIENT_PRIVATE_KEY_FILE):
    # Если ключи не существуют, создаём новые
    rsa_key_pair = RSA.generate(2048)
    
    # Сохраняем приватный ключ
    with open(CLIENT_PRIVATE_KEY_FILE, 'wb') as private_file:
        private_file.write(rsa_key_pair.export_key())
    
    # Сохраняем публичный ключ
    with open(CLIENT_PUBLIC_KEY_FILE, 'wb') as public_file:
        public_file.write(rsa_key_pair.publickey().export_key())
else:
    # Если ключи уже существуют, загружаем их из файлов
    with open(CLIENT_PRIVATE_KEY_FILE, 'rb') as private_file:
        rsa_key_pair = RSA.import_key(private_file.read())
    with open(CLIENT_PUBLIC_KEY_FILE, 'rb') as public_file:
        client_public_key = RSA.import_key(public_file.read())

# Приватный и публичный ключи клиента
client_private_key = rsa_key_pair
client_public_key = rsa_key_pair.publickey()

# Создание клиентского сокета и подключение к серверу
client_socket = socket.socket()
client_socket.connect((SERVER_HOST, SERVER_PORT))
print(f"Подключено к серверу {SERVER_HOST}:{SERVER_PORT}")

# Шаг 1. Отправка публичного ключа клиента серверу
client_socket.send(client_public_key.export_key())

# Шаг 2. Прием публичного ключа сервера
server_public_key_data = client_socket.recv(4096)  # Получение данных публичного ключа
server_public_key = RSA.import_key(server_public_key_data)  # Импорт ключа

# Шаг 3. Отправка зашифрованного сообщения серверу
message_to_server = "Привет от клиента!"  # Сообщение, которое отправляет клиент
rsa_cipher_for_server = PKCS1_OAEP.new(server_public_key)
encrypted_message = rsa_cipher_for_server.encrypt(message_to_server.encode())  # Шифрование сообщения
client_socket.send(encrypted_message)  # Отправка зашифрованного сообщения

# Шаг 4. Прием зашифрованного ответа от сервера
encrypted_server_response = client_socket.recv(4096)  # Получение зашифрованного ответа
rsa_cipher_for_client = PKCS1_OAEP.new(client_private_key)
decrypted_server_response = rsa_cipher_for_client.decrypt(encrypted_server_response)  # Расшифровка ответа
print(f"Ответ сервера: {decrypted_server_response.decode()}")  # Вывод ответа сервера

# Завершение работы клиента
client_socket.close()
