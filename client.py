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
from smartcards import *
from certificates import *
from OpenSSL import crypto
import pytz
import datetime

import re

import hmac
import base64


#variable initialization
BUFSIZE = 512 * 1024
client_name = ''
global K
K = -1
global pubkey
global rsa
rsa = None
global cid
cid = -1
global users_list
users_list = {}
global allmsglist
allmsglist = []

def connectToServer():
    global client_socket, client_name, privkey, pubkey, K
    client_name = raw_input('Please, insert your name: ')
    
    # Conection
    client_socket = socket(AF_INET, SOCK_STREAM)
    print 'Connecting to server...'
    client_socket.connect(('127.0.0.1', 8080))
    print 'Stablishing a secure connection...'

    print 'Stablishing session key...'
    data = None

    #waiting received A, g and p from server
    while True:
        rec = client_socket.recv(BUFSIZE)
        #se recebeu alguma coisa no socket
        if rec is not None:
            data = ast.literal_eval(rec)

            print "Received from server message %s" % data
            #verificar se a mensagem esta no formato correto
            if set({'A', 'g', 'p', 'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
                #verificar se os conteudos dos campos sao int
                if(isinstance(data['A'], int) and (isinstance(data['g'], int)) and (isinstance(data['p'], int))):
                    #verificar se os conteudos dos campos nao sao nulos
                    if((data['A'] != 0) and (data['g'] != 0) and (data['p'] != 0)):
                        break
            else:
                log(logging.ERROR, "Badly formated \"status\" message: " +
                    json.dumps(data))
                #client_socket.sendResult({"error": "wrong message format"})

    #verify if signature is valid
    print "Validations: \n"
    print " - Validating signature"
    c = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
    s = data['sign']
    sig = base64.decodestring(s)
    valid_sig = crypto.verify(c, sig, str(data['A']), "sha256")
    if valid_sig != None:
        print "Invalid Signature"
        #do something

    #validate signature time
    print " - Validating signature time"
    date1 = datetime.datetime.strptime(c.get_notAfter(), '%Y%m%d%H%M%SZ')
    date2 = datetime.datetime.strptime(data['datetime'], '%Y-%m-%dT%H:%M:%S.%f')
    date3 = datetime.datetime.strptime(c.get_notBefore(), '%Y%m%d%H%M%SZ')

    if date1 <= date2:
        print "Invalid signature time"
        #do something
    if date3 >= date2:
        print "Invalid signature time"
        #do something

    #verify if certificate is valid
    print " - Validating certificate and certificate chain"
    (is_valid, motive) = validateCertificate(c)
    #chain = generateCertChain(c)
    #valid_cert = verifyChain(chain, c)
    #if valid_cert != None:
    #    print "Certificate is not valid"
        #do something
    if not is_valid:
        print "Certificate is not valid"
        # do something


    #Calcular B = g^b mod p
    b = random.randint(2, 30)
    B = (data['g']**b)%data['p']

    #get signature private key from CC
    private_key = getCCPrivKey("CITIZEN SIGNATURE KEY")

    #Assinar B para enviar ao servidor
    print "Signing answer to server..."
    sig = signWithCC(private_key, str(B))
    dt = datetime.datetime.now()
    s = base64.encodestring(sig)

    #get citizen signature public key certificate
    pub_cert = getCertificate("CITIZEN SIGNATURE CERTIFICATE")
    signCert = crypto.load_certificate(crypto.FILETYPE_ASN1, pub_cert.as_der())

    #Mensagem dh para enviar B ao server
    msg = {'type' : 'dh', 'B' : B, 'cert' : crypto.dump_certificate(crypto.FILETYPE_PEM, signCert), 'sign': s, 'datetime': dt.isoformat()}

    print "Sending message to server: %s" % msg
    client_socket.send(json.dumps(msg) + "\r\n")

    #Calcular K = A^b mod p 
    K = (data['A']**b)%data['p']
    #skey = RSACipher(K, None, None)

    #espera confirmacao do servidor
    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            data = ast.literal_eval(rec)
            print "Received from server message %s" % data
            if set({'ok'}).issubset(set(data.keys())):
                #verificar se os conteudos dos campos sao str
                if(isinstance(data['ok'], str)):
                    #verificar se os conteudos dos campos nao sao nulos
                    if(data['ok'] != ""):
                        break
            else:
                log(logging.ERROR, "Badly formated \"status\" message: " +
                    json.dumps(data))

    if data['ok'] == "not ok":
        exit()

    msg = {'type' : 'dh','ok' : "ok"}
    client_socket.send(json.dumps(msg) + "\r\n")

    print '...Done'
    print 'Welcome client',client_name,'!\n'

    create_directory()

def main():
    printMenu()
    #option = raw_input('\nChose an option,' + client_name + ': ')
    option = raw_input('\nChose an option: ')
    process(option)

def printMenu():
    print '\n************************ MENU ************************ \n'
    print '1 - Request id'
    print '2 - Create a user message box'
    print '3 - List users messages boxes'
    print '4 - List new messages received'
    print '5 - List all messages received'
    print '6 - Send message to a user'
    print '7 - Receive a message from message box'
    print '8 - List messages sent and their receipts'
    print '9 - Exit from aplication'
    print '******************************************************'

def process(op):
    if op == '1':
        print 'Chosen 1 - Request id'
        request_id()
    if op == '2':
        print 'Chosen 2 - Create a user message box'
        create_user_message_box()
    elif op == '3':
        print 'Chosen 3 - List users messages boxes'
        list_users_msg()
    elif op == '4':
        print 'Chosen 4 - List new messages received'
        new_msg()
    elif op == '5':
        print 'Chosen 5 - List all messages received'
        new_all_msg()
    elif op == '6':
        print 'Chosen 6 - Send message to a user'
        send_msg()
    elif op == '7':
        print 'Chosen 7 - Receive a message from message box'
        recv_msg_from_mb()
    elif op == '8':
        print 'Chosen 8 - List message sent and their receipts'
        status()
    elif op == '9':
        print 'Chosen 9 - Exit from aplication'
        exit()
    else:
        print 'Option unrecognized'

    main()

#Request id
def request_id():
    global cid, rsa, K

    if not cid == -1:
        print "Your ID is: ", cid
        main()

    if rsa == None:
        read_keys()

    msg = {'type' : 'request', 'uuid' : base64.encodestring(getUuid())}

    msg_mac = encapsulate_msg(msg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")

    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            data = json.loads(rec)

            if isinstance(data, dict):
                break

    if not data['type'] == 'secure':
        print "Insecure message from server!"

    if not set({'type', 'payload', 'hmac'}).issubset(set(data.keys())):
        print "Invalid message format from server"

    payload = data['payload']

    p = base64.decodestring(payload)

    j = json.loads(p)

    if not set({'id'}).issubset(set(j.keys())):
        print "Error!"

    # check if hmac is correct
    h = hmac.new(hashlib.sha256(str(K)).digest(), '', hashlib.sha1)
    h.update(data['payload'])

    if hmac.compare_digest(base64.decodestring(data['hmac']), h.hexdigest()):

        if j['id'] == None:
            print 'User not created yet! Please, create a message box!'
        else:
            cid = int(j['id'])
            print 'Your ID is', cid

    main()


#Create user message box
def create_user_message_box():
    global pubkey, cid

    read_keys()
    public_key = base64.encodestring(pubkey)


    #uuid = '15'
    uuid = getUuid()
    uuid64 = base64.encodestring(uuid)
    '''
    pub_key_cert = getCertificate("CITIZEN SIGNATURE CERTIFICATE")
    signCert = crypto.load_certificate(crypto.FILETYPE_ASN1, pub_key_cert.as_der())
    '''
    if uuid is not None:


        #msg = {'type' : 'create', 'uuid' : uuid64, 'pubkey': crypto.dump_certificate(crypto.FILETYPE_PEM, signCert)}
        msg = {'type': 'create', 'uuid': uuid64, 'pubkey': public_key}

        client_socket.send(json.dumps(msg) + "\r\n")

        msg = {'type': 'create', 'uuid': uuid64, 'pubkey': public_key}

        msg_mac = encapsulate_msg(msg)

        client_socket.send(json.dumps(msg_mac) + "\r\n")

        data = client_socket.recv(BUFSIZE)

        res = ast.literal_eval(data)

        print "\n"
        if res.keys()[0] == "error":
            print res['error']
        else:
            cid = int(res['result'])
            print "Client ID: ", cid

    main()


#List users message boxes
def list_users_msg():
    global users_list, cid, pubkey
    nid = 0
    
    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    r = raw_input("Would you like to insert a specific ID?(Y/N): ")
    while r != 'Y' and r != 'y' and r != 'N' and r != 'n':
        print("Wrong answer!\n")
        r = raw_input("Would you like to insert a specific ID?(Y/N): ")

    if r == 'Y' or r == 'y':
        nid = raw_input("Insert ID: ")
        list = {'type' : 'list', 'id' : nid}
    else:
        list = {'type' : 'list'}

    msg_mac = encapsulate_msg(list)

    client_socket.send(json.dumps(msg_mac) + "\r\n")
    lst = client_socket.recv(BUFSIZE)

    lst = ast.literal_eval(lst)

    if lst.keys()[0] == "error":
        print(lst['error'])
    else:
        lista = lst['result']

    if nid == 0:
        users_list = {}
        for coiso in lista:
            users_list[str(coiso.keys()[0])] = coiso[str(coiso.keys()[0])]
    else:
        for coiso in lista:
            users_list[str(coiso[str(coiso.keys()[1])])] = coiso[str(coiso.keys()[0])]

    print users_list

    if set(users_list.keys()).issuperset(set({str(cid)})):
        if set(users_list[str(cid)].keys()).issuperset(set({'pubkey'})):
            pubkey = base64.decodestring(users_list[str(cid)]['pubkey'])
            print "\n"
            print pubkey
            print "\n"
    main()

#New messages
def new_msg():
    global cid

    if cid == -1:
        print "\nWrong client ID! Please, create a message or resquest id!"
        main()

    newmsg = {'type' : 'new', 'id' : cid}

    msg_mac = encapsulate_msg(newmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")
    newmsglst = client_socket.recv(BUFSIZE)
    print newmsglst

    newmsglst = ast.literal_eval(newmsglst)

    if "error" in newmsglst.keys():
        print(newmsglst['error'])
    else:
        newmsglist = newmsglst['result']
        print "List: ", newmsglist    

    main()

#All new messages
def new_all_msg():
    global cid, allmsglist

    if cid == -1:
        print "\nWrong client ID! Please, create a message or resquest id!"
        main()

    allmsg = {'type' : 'all', 'id' : cid}

    msg_mac = encapsulate_msg(allmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")
    allmsglst = client_socket.recv(BUFSIZE)

    allmsglst = ast.literal_eval(allmsglst)

    if "error" in allmsglst.keys():
        print "ERROR: ", allmsglst['error']
    else:
        allmsglist = allmsglst['result']
        print "All messages: ", allmsglist 

    main()

#Send message
def send_msg():
    global cid, K, users_list

    if K == -1:
        print "\nWrong Session Key! Please, try a new connection!"
        main()

    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    if users_list == {}:
        print "\nPlease, choose first \"3 - List users messages boxes\""
        main()

    flag = False
    while flag == False:

        dstid = raw_input("\nInsert destination ID: ")
        
        if set(users_list.keys()).issuperset(set({str(dstid)})):
            if cid != int(dstid):
                flag = True
            else:
                print "\nWrong destination ID! Your destination ID is equals to client ID"
        else:
            print "\nWrong destination ID!"

    txt = raw_input("Message: ")
    
    aes = AESCipher(K)
    msg = aes.encrypt(txt)

    pubkey_dst = base64.decodestring(users_list[str(dstid)]['pubkey'])
    dst_cipher = RSACipher(None, pubkey_dst)

    msg_key = dst_cipher.encrypt_pub(aes.key)

    aes_copy = AESCipher(K)
    copy_msg = aes_copy.encrypt(txt)
    copy_key = dst_cipher.encrypt_pub(aes_copy.key)

    sendmsg = {'type' : 'send', 'src' : cid, 'dst' : dstid, 'msg' : msg, 'copy' : copy_msg, 'msgkey' : msg_key, 'copykey' : copy_key}

    msg_mac = encapsulate_msg(sendmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")
    sendmsglst = client_socket.recv(BUFSIZE)
    
    print sendmsglst

    sendmsglst = ast.literal_eval(sendmsglst)
    if "error" in sendmsglst.keys():
        print "\nERROR: ", sendmsglst['error']
    else:
        print "\nSent message successfully!"
        print "Message ID: ",sendmsglst['result'][0]
        print "Receipt ID: ",sendmsglst['result'][1]

    main()

#Receive nessage from a user message box
def recv_msg_from_mb():
    global cid, rsa, allmsglist

    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    if rsa == None:
        read_keys()

    if allmsglist == []:
        print "\nPlease, choose first \"5 - List all messages received\""
        main()

    while True:
        msgid = raw_input("\nInsert message ID: ")
        
        pattern = "_?[0-9]+_[0-9]+"
        matches = re.match(pattern, msgid)
        
        if not matches:
            print "\nWrong format message ID!"
            print "Format: \"_Number_Number\" or \"Number_Number\""
        elif not msgid in allmsglist[0]:
            print "\nWrong message ID! Message not exists!"
            print "Available messages: ", allmsglist[0]
        else:
            break

    recvmsg = {'type' : 'recv', 'id' : cid, 'msg' : msgid}

    msg_mac = encapsulate_msg(recvmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")
    recvmsglst = client_socket.recv(BUFSIZE)

    print recvmsglst

    if "error" in ast.literal_eval(recvmsglst).keys():
        print "\nERROR: ", ast.literal_eval(recvmsglst)['error']
    else:
        recv = ast.literal_eval(ast.literal_eval(recvmsglst)['result'][1])
        msgrecv = AESCipher(None, rsa.decrypt_priv(recv['msgkey'])).decrypt(recv['msg'])
        print "\nMessage received: ", msgrecv
        # send receipt
        send_receipt(recvmsglst, msgid)

    main()


#Send receipt for a message
def send_receipt(res, msgid):
    global cid
    
    if cid == -1:
        print "\nWrong Client ID! Please, create a message or request id!"
        main()

    #get signature private key from CC
    private_key = getCCPrivKey("CITIZEN SIGNATURE KEY")

    # sign 
    sig = signWithCC(private_key, res)
    dt = datetime.datetime.now()
    s = base64.encodestring(sig)

    #get citizen signature public key certificate
    pub_cert = getCertificate("CITIZEN SIGNATURE CERTIFICATE")
    signCert = crypto.load_certificate(crypto.FILETYPE_ASN1, pub_cert.as_der())

    receiptmsg = {'type' : 'receipt', 'id' : cid, 'msg' : msgid, 'receipt' : s, 'cert' : crypto.dump_certificate(crypto.FILETYPE_PEM, signCert), 'datetime' : dt.isoformat()}

    msg_mac = encapsulate_msg(receiptmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")

    print "\nReceipt sent successfully!"

#Status
def status():
    global cid

    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    if allmsglist == []:
        print "\nPlease, choose first \"5 - List all messages received\""
        main()

    while True:
        msgid = raw_input("\nInsert message ID: ")
        
        pattern = "[0-9]+_[0-9]+"
        matches = re.match(pattern, msgid)
        
        if not matches:
            print "\nWrong format message ID!"
            print "Format: \"Number_Number\""
        elif not msgid in allmsglist[1]:
            print "\nWrong message ID! Message not exists!"
            print "Available messages: ", allmsglist[1]
        else:
            break

    statmsg = {'type' : 'status', 'id' : cid, 'msg' : msgid}

    msg_mac = encapsulate_msg(statmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")
    statmsglst = client_socket.recv(BUFSIZE)
    print statmsglst

    for i in ast.literal_eval(statmsglst)['result']['receipts']:
        if i['id'] == msgid[0]:
            print i['id'] # e agora??????????????????

    # verificar se msgid e igual ao id no result

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



def read_keys():
    global pubkey, rsa

    filename1 = directory + "/privkey.txt"

    if os.path.exists(filename1):
        try:
            file = open(filename1, 'r+')
            privkey = file.read()
            rsa = RSACipher(privkey, None)
        except OSError as e:
            log(logging.ERROR, str(e.errno))

        file.close()
    else:
        rsa = RSACipher(None, None)
        (privkey, pubkey) = rsa.create_asymmetric_key()
        rsa.privkey = privkey
        rsa.pubkey = pubkey
        print "Public Key: %s" % pubkey
        save_key(privkey, filename1)


def save_key(key, directory):

    try:
        file = open(directory, 'w+')
        file.write(key)
    except OSError as e:
        log(logging.ERROR, str(e.errno))

    file.close()

def getUuid():
    uuid = None
    cert = getCertificate("CITIZEN AUTHENTICATION CERTIFICATE")
    if cert is not None:
        try:
            uuid = hashlib.sha256(cert.as_pem()).digest()
        except Exception as e:
            print e
    return uuid

def encapsulate_msg(msg):
    # convert msg to base64
    msg64 = base64.encodestring(json.dumps(msg))

    # calcular hmac

    print K
    print hashlib.sha256(str(K)).digest()
    print hashlib.sha256(str(K)).digest()
    print hashlib.sha256(str(K)).digest()

    h = hmac.new(hashlib.sha256(str(K)).digest(), '', hashlib.sha1)
    h.update(msg64)

    print str(h)

    print "Msg64 = req['payload']"
    print msg64
    print "Digest Key"
    print hashlib.sha256(str(K)).digest()
    print "h"
    print h
    h1 = base64.encodestring(str(h))
    print "h1 = req['hmac']"
    print h1
    h2 = base64.decodestring(h1)
    print "h2 = d"
    print h2

    print "Comparacao"
    print h2==str(h)
    print hmac.compare_digest(h2, str(h))

    # send encapsulated msg
    return {'type': 'secure', 'payload': msg64, 'hmac': base64.encodestring(h.hexdigest())}


#Begin
try:
    print "Welcome!!"
    connectToServer()
    main()
except KeyboardInterrupt:
    pass
#.....