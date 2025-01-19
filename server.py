# ИСАДИЧЕВА Д.А., ДПИ22-1

import socket
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Конфигурация сервера
SERVER_HOST = '127.0.0.1'  # IP-адрес, на котором работает сервер
SERVER_PORT = 8080         # Порт, который слушает сервер
PRIVATE_KEY_FILE = "server_private.pem"  # Файл для хранения приватного ключа
PUBLIC_KEY_FILE = "server_public.pem"    # Файл для хранения публичного ключа

# Генерация или загрузка ключей RSA
if not os.path.exists(PRIVATE_KEY_FILE):
    # Если ключи не существуют, создаём новые
    rsa_key_pair = RSA.generate(2048)
    
    # Сохраняем приватный ключ
    with open(PRIVATE_KEY_FILE, 'wb') as private_file:
        private_file.write(rsa_key_pair.export_key())
    
    # Сохраняем публичный ключ
    with open(PUBLIC_KEY_FILE, 'wb') as public_file:
        public_file.write(rsa_key_pair.publickey().export_key())
else:
    # Если ключи уже существуют, загружаем их из файлов
    with open(PRIVATE_KEY_FILE, 'rb') as private_file:
        rsa_key_pair = RSA.import_key(private_file.read())
    with open(PUBLIC_KEY_FILE, 'rb') as public_file:
        server_public_key = RSA.import_key(public_file.read())

# Приватный и публичный ключи сервера
server_private_key = rsa_key_pair
server_public_key = rsa_key_pair.publickey()

# Создание серверного сокета
server_socket = socket.socket()
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(1)  # Прослушивание одного клиента
print(f"Сервер запущен и слушает на {SERVER_HOST}:{SERVER_PORT}")

# Ожидание подключения клиента
client_connection, client_address = server_socket.accept()
print(f"Клиент подключился: {client_address}")

# Шаг 1. Прием публичного ключа клиента
client_public_key_data = client_connection.recv(4096)  # Получение данных ключа
client_public_key = RSA.import_key(client_public_key_data)  # Импорт ключа

# Шаг 2. Отправка публичного ключа сервера клиенту
client_connection.send(server_public_key.export_key())

# Шаг 3. Прием зашифрованного сообщения от клиента
encrypted_message = client_connection.recv(4096)  # Получение зашифрованного сообщения

# Шаг 4. Расшифровка сообщения клиента
rsa_cipher_for_server = PKCS1_OAEP.new(server_private_key)
decrypted_message = rsa_cipher_for_server.decrypt(encrypted_message)
print(f"Получено зашифрованное сообщение: {decrypted_message.decode()}")

# Шаг 5. Формирование и отправка ответа клиенту
response_message = "Сообщение успешно получено!"  # Ответ сервера
rsa_cipher_for_client = PKCS1_OAEP.new(client_public_key)
encrypted_response_message = rsa_cipher_for_client.encrypt(response_message.encode())
client_connection.send(encrypted_response_message)  # Отправка зашифрованного ответа

# Завершение работы сервера
client_connection.close()
server_socket.close()
