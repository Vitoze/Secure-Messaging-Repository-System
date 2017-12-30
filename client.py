from socket import *
from select import *
import json
import sys
import time
import logging
import ast
import random
from primeGenerator import prime_root, primes
import hashlib
from ciphers import *
import os
import errno
from log import *
import ast

#variable initialization
BUFSIZE = 512 * 1024
client_name = ''
global K
K = 0
privkey = ''
symkey = ''
pubkey = ''
skey = None
aes = None
rsa = None

def connectToServer():
    global client_socket, client_name, privkey, symkey, pubkey, K, skey
    client_name = raw_input('Please, insert your name: ')
    
    # Conection
    client_socket = socket(AF_INET, SOCK_STREAM)
    print 'Connecting to server...'
    client_socket.connect(('127.0.0.1', 8080))

    data = None
    #waiting received A, g and p from server
    while True:
            rec = client_socket.recv(BUFSIZE)
            if rec is not None:
                data = ast.literal_eval(rec)
                #verificar se a mensagem esta no formato correto
                if set({'A', 'g', 'p'}).issubset(set(data.keys())):
                    #verificar se os conteudos dos campos sao int
                    if(isinstance(data['A'], int) and (isinstance(data['g'], int)) and (isinstance(data['p'], int))):
                        #verificar se os conteudos dos campos nao sao nulos
                        if((data['A'] != 0) and (data['g'] != 0) and (data['p'] != 0)):
                            break
                else:
                    log(logging.ERROR, "Badly formated \"status\" message: " +
                        json.dumps(data))
                    client_socket.sendResult({"error": "wrong message format"})

    #Calcular B = g^b mod p
    b = random.randint(2, 30)
    B = (data['g']**b)%data['p']
    
    #Mensagem dh para enviar B ao server
    msg = {'type' : 'dh', 'B' : B}
    client_socket.send(json.dumps(msg) + "\r\n")

    #Calcular K = A^b mod p 
    K = (data['A']**b)%data['p']
    skey = RSACipher(K, None, None)

    print '...Connected!'
    print 'Welcome client',client_name,'!\n'

    create_directory()
    read_keys()

def main():
    printMenu()
    #option = raw_input('\nChose an option,' + client_name + ': ')
    option = raw_input('\nChose an option: ')
    process(option)

def printMenu():
    print '\n************************ MENU ************************ \n'
    print '1 - Create a user message box'
    print '2 - List users messages boxes'
    print '3 - List new messages received by a user'
    print '4 - List all messages received by a user'
    print '5 - Send message to a user'
    print '6 - Receive a message from a user message box'
    print '7 - Send receipt for a message'
    print '8 - List messages sent and their receipts'
    print '9 - Exit from aplication'
    print '******************************************************'

def process(op):
    if op == '1':
        print 'Chosen 1 - Create a user message box'
        create_user_message_box()
    elif op == '2':
        print 'Chosen 2 - List users messages boxes'
        list_users_msg()
    elif op == '3':
        print 'Chosen 3 - List new messages received by a user'
        new_msg()
    elif op == '4':
        print 'Chosen 4 - List all messages received by a user'
    elif op == '5':
        print 'Chosen 5 - Send message to a user'
    elif op == '6':
        print 'Chosen 6 - Receive a message from a user message box'
    elif op == '7':
        print 'Chosen 7 - Send receipt for a message'
    elif op == '8':
        print 'Chosen 8 - List messages sent and their receipts'
    elif op == '9':
        print 'Chosen 9 - Exit from aplication'
        exit()
    else:
        print 'Option unrecognized'

    main()


#Create user message box
def create_user_message_box():
    global aes, skey

    uuid = '15'

    m = "{'type' : 'create', 'uuid' : %s}" % (uuid)
    
    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "create")

    encrypted_uuid = skey.encrypt_skey(uuid)
    msg = {'type' : 'create', 'uuid' : encrypted_uuid}   # uuid???
    client_socket.send(json.dumps(msg) + "\r\n")
    data = client_socket.recv(BUFSIZE)

    print("\n")

    data = ast.literal_eval(data)

    if data.keys()[0] == "error":
        print(data['error'])
    else:
        cid = int(skey.decrypt_skey(data['result']))
        print("Cliente Id: ", cid)
    
    main()

#List users message boxes
def list_users_msg():
    uuid = 4

    m = "{'type' : 'list'}"
    
    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "list")

    list = {'type' : 'list'}
    client_socket.send(json.dumps(list) + "\r\n")
    lst = client_socket.recv(BUFSIZE)
    print lst
    main()

#New messages
def new_msg():
    nid = 4

    m = "{'type' : 'new', 'id' : %s}" % (nid)
    
    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "new")

    newmsg = {'type' : 'new', 'id' : nid}
    client_socket.send(json.dumps(newmsg) + "\r\n")
    newmsglst = client_socket.recv(BUFSIZE)
    print newmsglst
    main()

#All new messages
def new_all_msg():
    nid = 4

    m = "{'type' : 'all', 'id' : %s}" % (nid)
    
    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "all")

    allmsg = {'type' : 'all', 'id' : nid}
    client_socket.send(json.dumps(allmsg) + "\r\n")
    allmsglst = client_socket.recv(BUFSIZE)
    print allmsglst
    main()

#Send message
def send_msg():
    sendmsg = {'type' : 'send', 'src' : '', 'dst' : '', 'msg' : json.dumps(''), 'copy' : json.dumps('')}
    client_socket.send(json.dumps(sendmsg) + "\r\n")
    sendmsglst = client_socket.recv(BUFSIZE)
    print sendmsglst
    main()

#Receive nessage from a user message box
def recv_msg_from_mb():
    nid = 4
    msg = ''

    m = "{'type' : 'recv', 'nid' : %s, 'msg' : %s}" % (nid, msg)
    
    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "recv")

    recvmsg = {'type' : 'recv', 'id' : nid, 'msg' : msg}
    client_socket.send(json.dumps(recvmsg) + "\r\n")
    recvmsglst = client_socket.recv(BUFSIZE)
    print recvmsglst
    main()


#Send receipt for a message
def send_receipt():
    nid = 4
    msg = ''
    receipt = ''

    m = "{'type' : 'receipt', 'id' : %s, 'msg' : %s, 'receipt' : %s}" % (nid, msg, receipt)
    
    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "receipt")

    receiptmsg = {'type' : 'receipt', 'id' : nid, 'msg' : msg, 'receipt' : receipt}
    client_socket.send(json.dumps(receiptmsg) + "\r\n")
    receiptmsglst = client_socket.recv(BUFSIZE)
    print receiptmsglst
    main()

#Status
def status():
    nid = 4
    msg = ''

    m = "{'type' : 'status', 'id' : %s, 'msg' : %s}" % (nid, msg)

    encrypted_m = aes.encrypt(m)
    write_msg(encrypted_m, "status")

    statmsg = {'type' : 'status', 'id' : nid, 'msg' : msg}
    client_socket.send(json.dumps(statmsg) + "\r\n")
    statmsglst = client_socket.recv(BUFSIZE)
    print statmsglst
    main()

def exit():
    sys.exit('\n***Client closed by your order')

def create_directory():
    global directory
    n = os.getcwd() + "/" + client_name + "/"
    directory = os.path.dirname(n)

    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError as e:
            log(logging.ERROR, str(e.errno))

def write_msg(msg, name):
    count = 0

    filename = directory + "/" + name + ".txt"
    while os.path.exists(filename):
        count += 1
        filename = directory + "/" + name + "(" + str(count) + ")" + ".txt"

    try:
        file = open(filename, 'w+')
        file.write(msg)
    except e:
        log(logging.ERROR, str(e.errno))

    file.close()


def read_keys():
    global privkey, pubkey, symkey, rsa, aes, k

    filename1 = directory + "/privkey.txt"
    filename2 = directory + "/symkey.txt"

    if os.path.exists(filename2):
        try:
            file = open(filename2, 'r+')
            symkey = file.read()
            aes = AESCipher(symkey)
        except OSError as e:
            log(logging.ERROR, str(e.errno))

        file.close()
    else:
        secret = hashlib.sha256(str(K)).digest()
        aes = AESCipher(secret)
        symkey = secret
        save_key(aes.key, filename2)

    if os.path.exists(filename1):
        try:
            file = open(filename1, 'r+')
            privkey = file.read()
            rsa = RSACipher(aes.key, privkey, None)
        except OSError as e:
            log(logging.ERROR, str(e.errno))

        file.close()
    else:
        rsa = RSACipher(secret, None, None)
        (privkey, pubkey) = rsa.create_asymmetric_key()
        rsa.privkey = privkey
        rsa.pubkey = pubkey
        save_key(privkey, filename1)


def save_key(key, directory):

    try:
        file = open(directory, 'w+')
        file.write(key)
    except OSError as e:
        log(logging.ERROR, str(e.errno))

    file.close()

#Begin
try:
    print "Welcome!!"
    connectToServer()
    main()
except KeyboardInterrupt:
    pass
#.....