import socket
import platform
import os
import sys
import subprocess
import signal
from time import sleep
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import threading
import datetime
import secrets
import string
import re
import json
import ctypes

os_info = {
        "OS Name": os.name,
        "System": platform.system(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Platform": platform.platform(),
        "Architecture": platform.architecture()[0]
    }
# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ""
server_port = 0
agent_name = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
agent_name_pattern = r"[^a-zA-Z0-9_]"

key = 0
nonce = 0

def start_conn():
    global agent_name
    global key
    global nonce

    # Get server address and port from user input
    name = input("Enter agent's name(a_z, A_Z, 0_9, _): ")
    if (re.search(agent_name_pattern,name)):
        print("*Invalid agent's name!")
        exit(1)
    if (len(name)!=0):
        agent_name = name
    print("*Your agent's name is: {}".format(agent_name))    

    server_address = input("Enter the server's IP address: ")
    server_port = int(input("Enter the server's communicate port: "))
    b_port = int(input("Enter the server's beacon port: "))

    key = base64.b64decode(input("Enter secret key: ").encode("utf-8"))
    nonce = base64.b64decode(input("Enter nonce: ").encode("utf-8"))

    try:
        # Connect to the server
        sock.connect((server_address, server_port))
        sleep(1)
        b_sock.connect((server_address, b_port))

        sec_sendall(nonce, sock, key, nonce)

        data = sec_recv(b_sock, key, nonce) # recv init_n
        if not data:
            print("*Can't connect to server, something wrong...\nHint: Check if secret key, nonce, server's IP, server's port or server side OK?")
            exit(1)
        
        sec_sendall(agent_name.encode(), sock, key, nonce) # send Agent's name
        sec_sendall(json.dumps(os_info).encode(), sock, key, nonce) # send Agent's name

        print("*Successfully connected to server {}:{}".format(server_address,server_port))
        beacon_thread = threading.Thread(target=handle_beacon, args=(int.from_bytes(data,byteorder='big'), b_sock))
        beacon_thread.start()

    except Exception as e:
        print(f"An error occurred: {e}")
    
def handle_beacon(init_n:int,sock:socket):
    while True:
        try:
            sleep(30)
            sec_sendall(init_n.to_bytes(64,byteorder='big'),sock, key, nonce)
            n = int.from_bytes(sec_recv(sock, key, nonce), byteorder='big')
            if (n - init_n == 1):
                init_n = n
            else:
                print("*Beacon invalid, please stop the agent for secure!")
                return
        except:
            print("*Beacon invalid, please stop the agent for secure!")
            return

def ask_privileges():
    os_type = platform.system()

    if os_type == "Windows":
        # Request admin privileges on Windows
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Need administrator privileges!\nHint: Run as administrator ...")
            exit(1)
    
    elif os_type == "Linux" or os_type == "Darwin":  # Darwin is macOS
        # Use sudo for Linux/macOS
        if os.geteuid() != 0:
            print("Need administrator privileges!\nHint: sudo ...")

def encrypt_mess(message: bytes, key: bytes, nonce: bytes) -> (bytes, bytes):
    # Initialize AES-GCM cipher with the key and nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the message and get the authentication tag
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag  # 16 bytes authentication tag
    
    return encrypted_message, tag

def sec_sendall(message: bytes, sock: socket, key, nonce):
    eMess, tag = encrypt_mess(message, key, nonce)
    send = json.dumps({"enc_mess":base64.b64encode(eMess).decode(),"tag":base64.b64encode(tag).decode()})
    s_len = len(send)
    sock.sendall(s_len.to_bytes(4, byteorder="big") + send.encode())

    return s_len

def decrypt_mess(encrypted_message: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    # Initialize AES-GCM cipher with the key, nonce, and tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    return decrypted_message

def sec_recv(sock: socket, key, nonce) -> bytes:
    d_len = int.from_bytes(sock.recv(4), byteorder="big")
    data = sock.recv(d_len)
    json_obj = json.loads(data)
    mess = decrypt_mess(base64.b64decode(json_obj["enc_mess"].encode()), key, nonce, base64.b64decode(json_obj["tag"].encode()))

    return mess

def excute_cmd(cmd_args: list):
   try:
    match cmd_args[0]:
        case "exec":
            return exec_cmd(cmd_args)
        case "agents":
            print()
        case _:
            print("*Command error!")
   except:
       print("*Command error!")
   return 0

def exec_cmd(cmd_args: list):
    cmd = cmd_args[1]
    if cmd[0] == "\"":
        cmd = cmd[1:]
        i = 2
        cmd += cmd_args[i]
        while cmd_args[i][-1] != "\"":
            i+=1
            agent_cmd += cmd_args[i]
        cmd = cmd[:-1]
    return subprocess.check_output(cmd, shell=True, text=True)
    
# start main
if __name__ == "__main__":
    ask_privileges()
    start_conn()
    while True:
        sec_sendall(excute_cmd(sec_recv(sock,key,nonce).decode().split()).encode(),sock,key,nonce)

'''
cmd response
'''