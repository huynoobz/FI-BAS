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
from concurrent.futures import ThreadPoolExecutor
import nmap
from scapy.all import ARP, Ether, srp
import io

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

attacks = ['ping_scan','syn_scan','udp_scan', 'arp_scan', 'ack_scan','fin_scan','xmas_scan','null_scan','vuln_scan','wordlist_scan','services_scan']

n_agents = 0

parameter_list = {}

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

if os_info["System"] == "Windows":
    nm_scanner = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap\\nmap.exe',))
else:
    nm_scanner = nmap.PortScanner()

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
    global com_port
    com_port = port

    port = b_sock.getsockname()[1]
    print("*Start beacon channel on port: {}".format(port))
    global bea_port
    bea_port = port
    
    # Listen for connections (optional)
    sock.listen(64)
    b_sock.listen(64)
    try:
        while True:
            client_socket, client_address = sock.accept()
            beacon_socket, client_address = b_sock.accept()
            beacon_socket.settimeout(60)

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
    try:
        d_len = int.from_bytes(sock.recv(4), byteorder="big")
        data = sock.recv(d_len)
        json_obj = json.loads(data)
        mess = decrypt_mess(base64.b64decode(json_obj["enc_mess"].encode()), key, nonce, base64.b64decode(json_obj["tag"].encode()))

        return mess
    except:
        return 

def sec_sendall2all(message: bytes, agents: list, key, nonce):
    for agent in agents:
        sec_sendall(message, agent.sock, key, nonce)

def ping_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")

    a = nm_scanner.scan(hosts=target_network, arguments='-sn')

    reachable_hosts = [host for host in nm_scanner.all_hosts() if nm_scanner[host].state() == "up"]

    c_a=0
    for agent in agents:
        if agent.address[0] in reachable_hosts:
            c_a+=1

    print("*There are {}/{} agents exposed by ping scan.".format(c_a,len(agents)))
    if c_a == len(agents) and c_a!=0:
        print("** Your network has NO defense against ping scan!")
    elif c_a > 0:
        print("** Your network can prevent A PART of ping scan!")
    elif len(reachable_hosts) == 0:
        print("** Your network ABSOLUTELY prevent against ping scan!")
        return False
    else:
        print("** Your network CAN prevent ping scan!")
    return True

def syn_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")
    
    nm_scanner.scan(hosts=target_network, ports='1-1000', arguments='-sS')

    results = {}
    
    for host in nm_scanner.all_hosts():
      if nm_scanner[host].state() == 'up':
                open_count = 0
                closed_count = 0
                filtered_count = 0            
                if 'tcp' in nm_scanner[host]:
                    for port, details in nm_scanner[host]['tcp'].items():
                        if details['state'] == 'open':
                            open_count += 1
                        elif details['state'] == 'closed':
                            closed_count += 1
                        elif 'filtered' in details['state']:
                            filtered_count += 1
                if closed_count == 0 and open_count+filtered_count!=1000:
                    closed_count = 1000 - open_count - filtered_count
                results[host] = [open_count, closed_count, filtered_count]

    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by SYN scan.".format(len(c_a),len(agents)))

    c=0
    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's exposed ports: {}/1000\n*Agent's exposed open ports: {}\n\n---\n"
                .format(i, 1000 - c_a[i][2], c_a[i][0]))
        if c_a[i][2] == 0:
            c+=1

    if c == len(agents) and c!=0:
        print("** Your agents have NO defense against SYN scan!")
    elif c > 0:
        print("** Your agents CAN prevent SYN scan!")
    elif c == 0:
        print("** Your agents ABSOLUTELY prevent against SYN scan!")
        return False
    return True
    
def udp_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")
    
    nm_scanner.scan(hosts=target_network, ports='1-1000', arguments='-sU')

    results = {}
    
    for host in nm_scanner.all_hosts():
      if nm_scanner[host].state() == 'up':
                open_count = 0
                closed_count = 0
                filtered_count = 0            
                if 'tcp' in nm_scanner[host]:
                    for port, details in nm_scanner[host]['tcp'].items():
                        if details['state'] == 'open':
                            open_count += 1
                        elif details['state'] == 'closed':
                            closed_count += 1
                        elif 'filtered' in details['state']:
                            filtered_count += 1
                if closed_count == 0 and open_count+filtered_count!=1000:
                    closed_count = 1000 - open_count - filtered_count
                results[host] = [open_count, closed_count, filtered_count]

    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by UDP scan.".format(len(c_a),len(agents)))

    c=0
    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's exposed ports: {}/1000\n*Agent's exposed open ports: {}\n\n---\n"
                .format(i, 1000 - c_a[i][2], c_a[i][0]))
        if c_a[i][2] == 0:
            c+=1

    if c == len(agents) and c!=0:
        print("** Your agents have NO defense against UDP scan!")
    elif c > 0:
        print("** Your agents CAN prevent UDP scan!")
    elif c == 0:
        print("** Your agents ABSOLUTELY prevent against UDP scan!")
        return False
    return True

def arp_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")

    # Create an ARP request packet
    arp_request = ARP(pdst=target_network)
    
    # Wrap it in an Ethernet frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the Ethernet frame and ARP request
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and capture responses
    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)
    
    # Parse responses
    reachable_hosts = []
    for sent, received in answered:
        reachable_hosts.append(received.psrc)
    
    c_a=0
    for agent in agents:
        if agent.address[0] in reachable_hosts:
            c_a+=1

    print("*There are {}/{} agents exposed by ARP scan.".format(c_a,len(agents)))
    if c_a == len(agents) and c_a!=0:
        print("** Your network has NO defense against ARP scan!")
    elif c_a > 0:
        print("** Your network can prevent A PART of ARP scan!")
    elif len(reachable_hosts) == 0:
        print("** Your network ABSOLUTELY prevent against ARP scan!")
        return False
    else:
        print("** Your network CAN prevent ARP scan!")
    return True

def ack_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")
    
    nm_scanner.scan(hosts=target_network, ports='1-1000', arguments='-sA')

    results = {}
    
    for host in nm_scanner.all_hosts():
      if nm_scanner[host].state() == 'up':
                open_count = 0
                closed_count = 0
                filtered_count = 0            
                if 'tcp' in nm_scanner[host]:
                    for port, details in nm_scanner[host]['tcp'].items():
                        if details['state'] == 'open':
                            open_count += 1
                        elif details['state'] == 'closed':
                            closed_count += 1
                        elif 'filtered' in details['state']:
                            filtered_count += 1
                if closed_count == 0 and open_count+filtered_count!=1000:
                    closed_count = 1000 - open_count - filtered_count
                results[host] = [open_count, closed_count, filtered_count]

    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by ACK scan.".format(len(c_a),len(agents)))

    c=0
    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's exposed ports: {}/1000\n*Agent's exposed open ports: {}\n\n---\n"
                .format(i, 1000 - c_a[i][2], c_a[i][0]))
        if c_a[i][2] == 0:
            c+=1

    if c == len(agents) and c!=0:
        print("** Your agents have NO defense against ACK scan!")
    elif c > 0:
        print("** Your agents CAN prevent ACK scan!")
    elif c == 0:
        print("** Your agents ABSOLUTELY prevent against ACK scan!")
        return False
    return True

def fin_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")
    
    nm_scanner.scan(hosts=target_network, ports='1-1000', arguments='-sF')

    results = {}
    
    for host in nm_scanner.all_hosts():
      if nm_scanner[host].state() == 'up':
                open_count = 0
                closed_count = 0
                filtered_count = 0            
                if 'tcp' in nm_scanner[host]:
                    for port, details in nm_scanner[host]['tcp'].items():
                        if details['state'] == 'open':
                            open_count += 1
                        elif details['state'] == 'closed':
                            closed_count += 1
                        elif 'filtered' in details['state']:
                            filtered_count += 1
                if closed_count == 0 and open_count+filtered_count!=1000:
                    closed_count = 1000 - open_count - filtered_count
                results[host] = [open_count, closed_count, filtered_count]

    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by FIN scan.".format(len(c_a),len(agents)))

    c=0
    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's exposed ports: {}/1000\n*Agent's exposed open ports: {}\n\n---\n"
                .format(i, 1000 - c_a[i][2], c_a[i][0]))
        if c_a[i][2] == 0:
            c+=1

    if c == len(agents) and c!=0:
        print("** Your agents have NO defense against FIN scan!")
    elif c > 0:
        print("** Your agents CAN prevent FIN scan!")
    elif c == 0:
        print("** Your agents ABSOLUTELY prevent against FIN scan!")
        return False
    return True

def xmas_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")
    
    nm_scanner.scan(hosts=target_network, ports='1-1000', arguments='-sX')

    results = {}
    
    for host in nm_scanner.all_hosts():
      if nm_scanner[host].state() == 'up':
                open_count = 0
                closed_count = 0
                filtered_count = 0            
                if 'tcp' in nm_scanner[host]:
                    for port, details in nm_scanner[host]['tcp'].items():
                        if details['state'] == 'open':
                            open_count += 1
                        elif details['state'] == 'closed':
                            closed_count += 1
                        elif 'filtered' in details['state']:
                            filtered_count += 1
                if closed_count == 0 and open_count+filtered_count!=1000:
                    closed_count = 1000 - open_count - filtered_count
                results[host] = [open_count, closed_count, filtered_count]

    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by Xmas scan.".format(len(c_a),len(agents)))

    c=0
    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's exposed ports: {}/1000\n*Agent's exposed open ports: {}\n\n---\n"
                .format(i, 1000 - c_a[i][2], c_a[i][0]))
        if c_a[i][2] == 0:
            c+=1

    if c == len(agents) and c!=0:
        print("** Your agents have NO defense against Xmas scan!")
    elif c > 0:
        print("** Your agents CAN prevent Xmas scan!")
    elif c == 0:
        print("** Your agents ABSOLUTELY prevent against Xmas scan!")
        return False
    return True

def null_scan():
    try:
        target_network = parameter_list['target_network']
    except:
        target_network = input("Enter target network (ex:192.168.1.0/24): ")
    
    nm_scanner.scan(hosts=target_network, ports='1-1000', arguments='-sX')

    results = {}
    
    for host in nm_scanner.all_hosts():
      if nm_scanner[host].state() == 'up':
                open_count = 0
                closed_count = 0
                filtered_count = 0            
                if 'tcp' in nm_scanner[host]:
                    for port, details in nm_scanner[host]['tcp'].items():
                        if details['state'] == 'open':
                            open_count += 1
                        elif details['state'] == 'closed':
                            closed_count += 1
                        elif 'filtered' in details['state']:
                            filtered_count += 1
                if closed_count == 0 and open_count+filtered_count!=1000:
                    closed_count = 1000 - open_count - filtered_count
                results[host] = [open_count, closed_count, filtered_count]

    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by NULL scan.".format(len(c_a),len(agents)))

    c=0
    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's exposed ports: {}/1000\n*Agent's exposed open ports: {}\n\n---\n"
                .format(i, 1000 - c_a[i][2], c_a[i][0]))
        if c_a[i][2] == 0:
            c+=1

    if c == len(agents) and c!=0:
        print("** Your agents have NO defense against NULL scan!")
    elif c > 0:
        print("** Your agents CAN prevent NULL scan!")
    elif c == 0:
        print("** Your agents ABSOLUTELY prevent against NULL scan!")
        return False
    return True

def vuln_scan():
    hosts = []
    for agent in agents:
        hosts.append(agent.address[0])
        
    results = {}

    nm_scanner.scan(hosts=','.join(hosts), arguments='--script vuln')
    for host in nm_scanner.all_hosts():
        results[host] = 0
        for protocol in nm_scanner[host].all_protocols():
            lport = nm_scanner[host][protocol].keys()
            for port in lport:
                # Check for vulnerability scan output
                if 'script' in nm_scanner[host][protocol][port]:
                    for script in nm_scanner[host][protocol][port]['script']:
                        if 'VULNERABLE' in script:
                            results[host] +=1
    
    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by vulnerability scan.".format(len(c_a),len(agents)))

    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's vulnerabilities: {}\n\n---\n"
                .format(i, c_a[i]))

    if len(c_a) == len(agents) and len(c_a)!=0:
        print("** Your agents have NO defense against vulnerability scan!")
    elif len(c_a) > 0:
        print("** Your agents CAN prevent vulnerability scan!")
    elif len(c_a) == 0:
        print("** Your agents ABSOLUTELY prevent against vulnerability scan!")
        return False
    return True

def wordlist_scan():
    hosts = []
    for agent in agents:
        hosts.append(agent.address[0])
        
    results = {}

    nm_scanner.scan(hosts=','.join(hosts), arguments='--script http-enum')
    for host in nm_scanner.all_hosts():
        results[host] = 0
        for protocol in nm_scanner[host].all_protocols():
            lport = nm_scanner[host][protocol].keys()
            for port in lport:
                try:
                    results[host] += nm_scanner[host][protocol][port]['script']['http-enum'].count('\n') - 1
                except:
                    pass                        
    
    c_a={}
    for agent in agents:
        if agent.address[0] in results.keys():
            c_a[agent.id]=results[agent.address[0]]

    print("*There are {}/{} agents exposed by wordlist scan.".format(len(c_a),len(agents)))

    for i in c_a.keys():
        print("*Agent's id: {}\n*Agent's common words: {}\n\n---\n"
                .format(i, c_a[i]))

    if len(c_a) == len(agents) and len(c_a)!=0:
        print("** Your agents have NO defense against wordlist scan!")
    elif len(c_a) > 0:
        print("** Your agents CAN prevent wordlist scan!")
    elif len(c_a) == 0:
        print("** Your agents ABSOLUTELY prevent against wordlist scan!")
        return False
    return True

def services_scan():
    hosts = []
    for agent in agents:
        hosts.append(agent.address[0])
        
    results = {}

    nm_scanner.scan(hosts=','.join(hosts), arguments='-sV -Pn -T5')
    for agent in agents:
        agent_cmd = "simulate services_scan"
        sec_sendall(agent_cmd.encode(),agent.sock, key, nonce)
        agent_ans = eval(sec_recv(agent.sock,key,nonce).decode())
        results[agent.id] = [0,len(agent_ans['tcp'])]
        for dic in nm_scanner[agent.address[0]]['tcp']:
            if str(dic)[1:-1] in str(agent_ans['tcp']):
                results[agent.id][0] +=1
        print("*Agent's id: {}\n*Agent's exposed services: {}/{}\n\n---\n"
                .format(agent.id, results[agent.id][0], results[agent.id][1]))

    c=0
    for res in results.keys():
        if results[res][0] == 0:
            c+=1     
        else:
            break
    if c==len(results):
        print("** Your agents ABSOLUTELY prevent against services scan!")
        return False
    
    c=0
    for res in results.keys():
        if results[res][0] == results[res][1]:
            c+=1     
        else:
            break
    if c == len(results):
        print("** Your agents have NO defense against services scan!")
    else:
        print("** Your agents CAN prevent services scan!")
    return True
    
def excute_cmd(cmd_args: list): ###
   try:
    match cmd_args[0]:
        case "":
            return
        case "set_para":
            set_para_cmd(cmd_args)
        case "simulate":
            simulate_cmd(cmd_args)
        case "agents":
            agents_cmd(cmd_args)
        case "server":
            server_cmd(cmd_args)
        case "agent_exec":
            agent_exec_cmd(cmd_args)
        case "ba_list":
            print("Breach and attack list:",attacks)
        case "help":
            with open("help.txt",'r') as help_:
                print(help_.read())
        case _:
            print("*Unknown command. Please type \"help\" for help.")
   except:
    print("*Error command. Please type \"help\" for help.")

def simulate_cmd(cmd_args: list):
   try:
    match cmd_args[1]:
        case "all":
            brief = False
            try:
                if cmd_args[2] == 'brief':
                    brief = True
            except:
                pass

            if brief:
                try:
                    target_network = parameter_list['target_network']
                except:
                    parameter_list['target_network'] = input("Enter target network (ex:192.168.1.0/24): ")
                    target_network = parameter_list['target_network']

                for attack in attacks:
                    if len(agents) == 0: 
                        print("* No agents!!!")
                        return

                    if attack in globals():
                        old_stdout = sys.stdout
                        sys.stdout = io.StringIO()
                        if globals()[attack]():
                            res = "SUCCESS"
                        else:
                            res = "FAILED"
                        sys.stdout = old_stdout
                    print("#{} - {}".format(attack, res))

            else:
                for attack in attacks:
                    if len(agents) == 0: 
                        print("* No agents!!!")
                        return
                    print("#{}".format(attack))
                    if attack in globals():
                        globals()[attack]()
                    print("\n------\n")
        
        case "help":
            with open("help.txt",'r') as help_:
                print(help_.read())
        case _:
            if cmd_args[1] in globals():
                try:
                    globals()[cmd_args[1]]()
                except:
                    print("*Error {}!".format(cmd_args[1]))
            else:
                print("*Unknown simulate. Please type \"help\" for help.")
   except:
    print("*Error simulate!")


def set_para_cmd(cmd_args: list):
   global parameter_list

   if cmd_args[1] == 'list':
       print(parameter_list)
       return

   try:
    paras = cmd_args[1:]
    for para in paras:
        a = para.split('=')
        parameter_list[a[0]] = a[1]
   except:
        print("*set_para error. Please type \"help\" for help.")

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
            print("*agent_exec error. Please type \"help\" for help.")

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
            print("Server's communicate port: {}\nServer's beacon port: {}\nServer's secret key: {}\nServer's nonce: {}\nServer's OS info:"
                  .format(com_port,bea_port,base64.b64encode(key).decode("utf-8"),base64.b64encode(nonce).decode("utf-8")))
            for key_, value in os_info.items():
                print("{}: {}".format(key_,value))
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
        cmd = input("> ")
        cmd_args = cmd.split()
        print("***")
        excute_cmd(cmd_args)

'''
LOCK FOR SHARED VARIABLE
more cmd
'''

