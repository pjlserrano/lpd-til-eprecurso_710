#!/usr/bin/env python3
#
# MESI - Mestrado em Engenharia de Segurança da Informação 
# Linguagem de Programação Dinâmica - LPD - Projeto Python
# Aluno: Paulo Serrano - 710
#
# Módulo: server.py - modulo para troca de mensagem segura, lado servidor
# Exibe o resultao na tela
# Criado em 06/03/2026
# Historio de modificacoes:
#
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

HOST = "0.0.0.0"
PORT = 9000

# Geração de chaves RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("[+] Servidor seguro iniciado")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)

conn, addr = sock.accept()
print(f"[+] Cliente conectado: {addr}")

# Envia chave pública
conn.sendall(public_pem)

# Recebe chave AES cifrada
encrypted_aes = conn.recv(256)
aes_key = private_key.decrypt(
    encrypted_aes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

cipher = Fernet(aes_key)
print("[+] Canal seguro estabelecido")

while True:
    data = conn.recv(4096)
    if not data:
        break

    message = cipher.decrypt(data).decode()
    print(f"Cliente: {message}")

    if message == "Fim comunicacao":
        response = cipher.encrypt(b"Comunicacao encerrada pelo servidor")
        conn.sendall(response)
        break

    response = cipher.encrypt(f"Recebido: {message}".encode())
    conn.sendall(response)

conn.close()
sock.close()
print("[+] Conexao encerrada com sucesso")

