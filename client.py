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

#variable initialization
BUFSIZE = 512 * 1024
client_name = ''
global K
K = 0
privkey = ''
symkey = ''
global pubkey
global rsa
global users_list
users_list = {}

def connectToServer():
    global client_socket, client_name, privkey, pubkey, K
    client_name = raw_input('Please, insert your name: ')
    
    # Conection
    client_socket = socket(AF_INET, SOCK_STREAM)
    print 'Connecting to server...'
    client_socket.connect(('127.0.0.1', 8080))
    print 'Stablishing a secure connection...'

    data = None
    #waiting received A, g and p from server
    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            #lst = rec.split(',')
            #data_string = lst[0] + ',' + lst[1] + ',' + lst[2] + '}'
            #print str
            data = ast.literal_eval(rec)
            #verificar se a mensagem esta no formato correto
            #if lst[3].startswith('"cert"'):
                #if lst[4].startswith('"sign"'):
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
    #cert = M2Crypto.X509.load_cert_string(lst[3][7:])
    c = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
    s = data['sign']
    print s
    print len(s)
    sig = base64.decodestring(s)
    valid_sig = crypto.verify(c, sig, str(data['A']), "sha256")
    if valid_sig != None:
        print "Invalid Signature"

    #validate signature time
    print type(c.get_notAfter())
    print c.get_notAfter()
    print type(data['datetime'])
    print data['datetime']
    date1 = datetime.datetime.strptime(c.get_notAfter(), '%Y%m%d%H%M%SZ')
    date2 = datetime.datetime.strptime(data['datetime'], '%Y-%m-%dT%H:%M:%S.%f')
    date3 = datetime.datetime.strptime(c.get_notBefore(), '%Y%m%d%H%M%SZ')
    #print date1 <= date2

    if date1 <= date2:
        print "Invalid signature time"
    if date3 >= date2:
        print "Invalid signature time"

    #verify if certificate is valid
    chain = generateCertChain(c)
    valid_cert = verifyChain(chain, c)
    if valid_cert != None:
        print "Cannot validate certificate with given chain"


    #Calcular B = g^b mod p
    b = random.randint(2, 30)
    B = (data['g']**b)%data['p']

    #get signature private key from CC
    private_key = getCCPrivKey("CITIZEN SIGNATURE KEY")

    #Assinar B para enviar ao servidor
    sig = signWithCC(private_key, str(B))
    dt = datetime.datetime.now()
    s = base64.encodestring(sig)
    print sig
    print len(s)

    #get citizen signature public key certificate
    pub_cert = getCertificate("CITIZEN SIGNATURE CERTIFICATE")
    print "Signature"
    print pub_cert.as_der()
    print pub_cert.as_pem()
    signCert = crypto.load_certificate(crypto.FILETYPE_ASN1, pub_cert.as_der())
    print crypto.dump_certificate(crypto.FILETYPE_PEM, signCert)
    #Mensagem dh para enviar B ao server
    msg = {'type' : 'dh', 'B' : B, 'cert' : crypto.dump_certificate(crypto.FILETYPE_PEM, signCert), 'sign': s, 'datetime': dt.isoformat()}
    #msg = {'type': 'dh', 'B': B, 'cert': pub_cert.as_pem, 'sign': s}

    #tmp = json.dumps(msg)

    # print tmp

    #tmp2 = tmp[:len(tmp) - 1]
    #tmp3 = tmp2 + ',"cert":' + crypto.dump_certificate(crypto.FILETYPE_PEM, signCert) + ',"sign":' + s + "}"
    client_socket.send(json.dumps(msg) + "\r\n")

    #Calcular K = A^b mod p 
    K = (data['A']**b)%data['p']
    #skey = RSACipher(K, None, None)

    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            data = ast.literal_eval(rec)
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
        print 'Chosen  - Send message to a user'
        send_msg()
    elif op == '7':
        print 'Chosen 7 - Receive a message from message box'
        recv_msg_from_mb()
    elif op == '8':
        print 'Chosen 8 - List messages sent and their receipts'
        send_receipt()
    elif op == '9':
        print 'Chosen 9 - Exit from aplication'
        exit()
    else:
        print 'Option unrecognized'

    main()

#Request id
def request_id():
    global cid

    msg = {'type' : 'request', 'uuid' : base64.encodestring(getUuid())}
    client_socket.send(json.dumps(msg) + "\r\n")

    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            data = ast.literal_eval(rec)
            if not set({'id'}).issubset(set(data.keys())):
                log(logging.ERROR, "Badly formated \"status\" message: " +
                    json.dumps(data))
            else:
                break

    if data['id'] == None:
        print 'User not created yet! Please, create a message box!'
    else:
        cid = int(data['id'])
        print 'Your ID is', cid

    main()


#Create user message box
def create_user_message_box():
    global pubkey

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

        #m = "{'type' : 'create', 'uuid' : %s, }" % (uuid)

        #encrypted_m = aes.encrypt(m)
        #write_msg(encrypted_m, "create")

        #msg = {'type' : 'create', 'uuid' : uuid64, 'pubkey': crypto.dump_certificate(crypto.FILETYPE_PEM, signCert)}
        msg = {'type': 'create', 'uuid': uuid64, 'pubkey': public_key}
        #encrypted_m = skey.encrypt_skey(msg)
        #print encrypted_m
        client_socket.send(json.dumps(msg) + "\r\n")
        data = client_socket.recv(BUFSIZE)

        res = ast.literal_eval(data)

        print "\n"
        if res.keys()[0] == "error":
            print res['error']
        else:
            cid = int(res['result'])
            print "Cliente Id: ", cid

    main()


#List users message boxes
def list_users_msg():
    global users_list, cid, pubkey
    print("\n")
    nid = 0
    
    r = raw_input("Deseja introduzir um ID especifico?(Y/N): ")
    while r != 'Y' and r != 'y' and r != 'N' and r != 'n':
        print("Wrong answer!\n")
        r = raw_input("Deseja introduzir um ID especifico?(Y/N): ")

    if r == 'Y' or r == 'y':
        nid = raw_input("Introduza o ID: ")
        #encrypted_nid = skey.encrypt_skey(str(nid))
        list = {'type' : 'list', 'id' : nid}
    else:
        list = {'type' : 'list'}

    client_socket.send(json.dumps(list) + "\r\n")
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

    #encrypted_nid = skey.encrypt_skey(str(cid))

    newmsg = {'type' : 'new', 'id' : cid}
    
    client_socket.send(json.dumps(newmsg) + "\r\n")
    newmsglst = client_socket.recv(BUFSIZE)
    print newmsglst

    newmsglst = ast.literal_eval(newmsglst)

    if newmsglst.keys()[0] == "error":
        print(newmsglst['error'])
    else:
        newmsglist = newmsglst['result']
        print "Lista: ", newmsglist    

    main()

#All new messages
def new_all_msg():
    global cid

    #encrypted_nid = skey.encrypt_skey(str(cid))

    allmsg = {'type' : 'all', 'id' : cid}

    client_socket.send(json.dumps(allmsg) + "\r\n")
    allmsglst = client_socket.recv(BUFSIZE)
    print allmsglst

    allmsglst = ast.literal_eval(allmsglst)

    if allmsglst.keys()[0] == "error":
        print(allmsglst['error'])
    else:
        allmsglist = allmsglst['result']
        print("Lista: ", allmsglist) 

    main()

#Send message
def send_msg():
    global cid, K, users_list

    dstid = raw_input("Introduza o ID do destinatario ")
    txt = raw_input("Mensagem: ")
    
    aes = AESCipher(K)
    msg = aes.encrypt(txt)

    pubkey_dst = base64.decodestring(users_list[str(dstid)]['pubkey'])
    dst_cipher = RSACipher(None, pubkey_dst)

    msg_key = dst_cipher.encrypt_pub(aes.key)

    aes_copy = AESCipher(K)
    copy_msg = aes_copy.encrypt(txt)
    copy_key = dst_cipher.encrypt_pub(aes_copy.key)

    sendmsg = {'type' : 'send', 'src' : cid, 'dst' : dstid, 'msg' : msg, 'copy' : copy_msg, 'msgkey' : msg_key, 'copykey' : copy_key}
    client_socket.send(json.dumps(sendmsg) + "\r\n")
    sendmsglst = client_socket.recv(BUFSIZE)
    print sendmsglst
    main()

#Receive nessage from a user message box
def recv_msg_from_mb():
    nid = 4
    msg = ''

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

    receiptmsg = {'type' : 'receipt', 'id' : nid, 'msg' : msg, 'receipt' : receipt}
    client_socket.send(json.dumps(receiptmsg) + "\r\n")
    receiptmsglst = client_socket.recv(BUFSIZE)
    print receiptmsglst
    main()

#Status
def status():
    nid = 4
    msg = ''

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



def read_keys():
    global privkey, pubkey, rsa

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


#Begin
try:
    print "Welcome!!"
    connectToServer()
    main()
except KeyboardInterrupt:
    pass
#.....