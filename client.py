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
from fileenc_openssl import stretch_key, encrypt_file, decrypt_file
import re
import hmac
import base64
import getpass


#variable initialization
BUFSIZE = 512 * 1024
global client_name
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
global password
password = ""
global server_cert
server_cert = None
global client_socket
client_socket= None


def connectToServer():
    global client_socket, client_name, privkey, pubkey, K, server_cert, cid, users_list, allmsglist

    pubkey = None
    cid = -1
    users_list = {}
    allmsglist = []
    server_cert = None

    # Conection
    client_socket = socket(AF_INET, SOCK_STREAM)
    print 'Connecting to server...'
    client_socket.connect(('127.0.0.1', 8080))

    data = None

    #waiting received A, g and p from server
    while True:
        rec = client_socket.recv(BUFSIZE)
        #se recebeu alguma coisa no socket
        print 'Stablishing session key...'
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

    # verify if signature is valid
    valid_sig = validateServerSig(data['cert'], data['A'], data['sign'], data['datetime'])
    if not valid_sig:
        print "Signature is not valid"
        print "\nCommunication may be compromised.\nClosing connection and opening a new one."
        client_socket.close()
        connectToServer()

    #Calcular B = g^b mod p
    b = random.randint(2, 30)
    B = (data['g']**b)%data['p']

    seqnumber = random.randint(0, 1500)

    msg = {'type': 'dh', 'B': B, 'sn': seqnumber}

    # sign B to send to server
    print "Signing %s to send to server" % msg
    userSignMessage('B', msg)

    print "Sending message to server: %s" % msg
    client_socket.send(json.dumps(msg) + "\r\n")

    #Calcular K = A^b mod p 
    K = (data['A']**b)%data['p']

    data = {}
    #espera confirmacao do servidor
    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            try:
                data = ast.literal_eval(rec)
                print "Received from server message %s" % data
                break
            except:
                continue

    if set({'sn'}).issubset(set(data.keys())) and data['sn'] == seqnumber + 1:
        if set({'ok','cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            # verify if signature is valid
            valid_sig = validateServerSig(data['cert'], data['ok'], data['sign'], data['datetime'])
            if valid_sig:
                if data['ok'] == "not ok":
                    print "Session key was not stablished. Starting the process again."
                    client_socket.close()
                    connectToServer()
                elif data['ok'] == "ok":
                    msg = {'type': 'dh', 'ok': "ok"}


                    server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])

                    # sign ok to send to server
                    print "Signing %s to send to server" % msg
                    userSignMessage('ok', msg)

                    print "Sending message to server: %s" % msg
                    client_socket.send(json.dumps(msg) + "\r\n")
                else:
                    print "Message received was not expected."
                    print "Session key was not stablished. Starting the process again."
                    client_socket.close()
                    connectToServer()
            else:
                print "Signature is not correct!"

                client_socket.close()
                connectToServer()
        else:
            if set({'error', 'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(data['cert'], data['error'], data['sign'], data['datetime'])
                if valid_sig:
                    print "ERROR: ", data['error']
                else:
                    print "Signature is not correct!"
                    client_socket.close()
                    connectToServer()
            else:
                print "Message received was not in the expected format"
                print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                client_socket.close()
                connectToServer()
    else:
        print "\nSequence number is not valid!"
        print "Session key was not stablished. Starting the process again."
        client_socket.close()
        connectToServer()

    '''
            if set({'ok', 'cert', 'sign', 'datetime', 'sn'}).issubset(set(data.keys())):
                #verificar se os conteudos dos campos sao str
                if(isinstance(data['ok'], str)):
                    #verificar se os conteudos dos campos nao sao nulos
                    if(data['ok'] != ""):
                        break
            elif "error" in data.keys():
                if set({'cert', 'sign', 'datetime', 'sn'}).issubset(set(data.keys())):
                    # verify if signature is valid
                    valid_sig = validateServerSig(data['cert'], data['ok'], data['sign'], data['datetime'])
                    if valid_sig:
                        print "ERROR: ", data['error']

                else:
                    print "Message received is not in the expected format."
                    client_socket.close()
                    connectToServer()
            else:
                print "Message received is not in the expected format."
                client_socket.close()
                connectToServer()

    print "Received %s from server" % data

    if set({'sn'}).issubset(set(data.keys())) and data['sn'] == seqnumber+1:
        if set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            # verify if signature is valid

            valid_sig = validateServerSig(data['cert'], data['ok'], data['sign'], data['datetime'])

            if valid_sig:
                if data['ok'] == "not ok":
                    exit()

                msg = {'type': 'dh', 'ok': "ok"}

                #sign ok to send to server
                print "Signing %s to send to server" % msg
                userSignMessage('ok', msg)

                print "Sending message to server: %s" % msg
                client_socket.send(json.dumps(msg) + "\r\n")
            else:
                print "Signature is not correct!"
        else:
            print "No signature field in server message"
            # do something
    else:
        print "\nSequence number is not valid!"
    '''
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
        print 'Chosen 8 - Check message status'
        status()
    elif op == '9':
        print 'Chosen 9 - Exit from aplication'
        exit()
    else:
        print 'Option unrecognized'

    main()

#Request id
def request_id():
    global cid, rsa, K, password, server_cert

    seqnumber = random.randint(0, 1500)

    if not existsDirectory():
        print "\nPlease, first choose the option 2 - Create a user message box!"
        main()

    if not cid == -1:
        print "\nYour client ID is:", cid
        main()

    if rsa == None:
        while True:
            password = getpass.getpass("\nInsert your password to read your keys: ")
        
            if password == "":
                print "\nWrong password! Password is empty!" 
            else:
                break
                    
        read_keys(password)

    msg = {'type' : 'request', 'sn' : seqnumber, 'uuid' : base64.encodestring(getUuid())}

    #sign uuid to send to server
    print "Signing %s to send to server" % msg
    userSignMessage('uuid', msg)

    msg_mac = encapsulate_msg(msg)

    #print "Sending message to server: %s" % msg
    client_socket.send(json.dumps(msg_mac) + "\r\n")

    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            try:
                data = ast.literal_eval(rec)
                break
            except:
                continue

    if not data['type'] == 'secure':
        print "\nInvalid message from server!"
        #do nothing
    else:
        if not set({'type', 'payload', 'hmac'}).issubset(set(data.keys())):
            print "\nInvalid message format from server"
            #do nothing
        else:
            payload = data['payload']

            p = base64.decodestring(payload)

            j = ast.literal_eval(p)

            print "Received %s from server" % j

            # check if hmac is correct
            if verify_HMAC(data):

                if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber+1:
                    if set({'id', 'sign', 'datetime'}).issubset(set(j.keys())):
                        # verify if signature is valid
                        valid_sig = validateServerSig(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert), j['id'], j['sign'], j['datetime'])
                        if valid_sig:
                            if j['id'] == None:
                                print '\nUser not created yet! Please, create a message box!'
                            else:
                                cid = int(j['id'])
                                print '\nYour client ID is', cid
                        else:
                            print "Signature is not correct!"
                            print "\nCommunication may be compromised.\nClosing connection.\nGood bye!"
                            client_socket.close()
                            connectToServer()

                    elif set({'error', 'sign', 'datetime'}).issubset(set(j.keys())):
                        # verify if signature is valid
                        valid_sig = validateServerSig(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert), j['error'], j['sign'], j['datetime'])
                        if valid_sig:
                            print "ERROR: ", j['error']
                            # do nothing
                    else:
                        print "Invalid Message from server"
                else:
                    print "\nSequence number is not valid!"
            else:
                print "\nMessage does not match to HMAC"
                print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                client_socket.close()
                connectToServer()

    main()

#Create user message box
def create_user_message_box():
    global pubkey, cid, password

    seqnumber = random.randint(0, 1500)

    create_directory()

    if existsDirectory():
        print "\nYour message box already exists!"
        main()

    password = getpass.getpass("\nInsert one password to encrypt your personal files: ")
    read_keys(password)
    public_key = base64.encodestring(pubkey)

    uuid = getUuid()
    uuid64 = base64.encodestring(uuid)
    '''
    pub_key_cert = getCertificate("CITIZEN SIGNATURE CERTIFICATE")
    signCert = crypto.load_certificate(crypto.FILETYPE_ASN1, pub_key_cert.as_der())
    '''
    if uuid is not None:

        msg = {'type': 'create', 'sn': seqnumber, 'uuid': uuid64, 'pubkey': public_key}

        # sign uuid to send to server
        print "Signing %s to send to server" % msg
        userSignMessage('uuid', msg)

        msg_mac = encapsulate_msg(msg)

        client_socket.send(json.dumps(msg_mac) + "\r\n")

        data=''

        while True:
            rec = client_socket.recv(BUFSIZE)
            if rec is not None:
                try:
                    data = ast.literal_eval(rec)
                    if isinstance(data, dict):
                        break
                except:
                    continue

        if not data['type'] == 'secure':
            print "\nInvalid message from server!"

        if not set({'type', 'payload', 'hmac'}).issubset(set(data.keys())):
            print "\nInvalid message format from server"

        payload = data['payload']

        p = base64.decodestring(payload)

        j = ast.literal_eval(p)

        print "Received %s from server" % j

        if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber + 1:
            # check if hmac is correct
            if verify_HMAC(data):
                if set({'error', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                    # verify if signature is valid
                        valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                        if valid_sig:
                            print "ERROR: ", j['error']
                            deleteDirectory()
                        else:
                            print "Signature is not correct!"
                            deleteDirectory()
                            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                            client_socket.close()
                            connectToServer()

                elif set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                        # verify if signature is valid
                        valid_sig = validateServerSig(j['cert'], j['result'], j['sign'], j['datetime'])
                        if valid_sig:
                            cid = int(j['result'])
                            print "\nClient ID: ", cid
                        else:
                            print "Signature is not correct!"
                            deleteDirectory()
                            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                            client_socket.close()
                            connectToServer()
                else:
                    print "Invalid message from server"
                    deleteDirectory()
            else:
                print "\nMessage does not match to HMAC"
                deleteDirectory()
                print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                client_socket.close()
                connectToServer()
        else:
            print "\nSequence number is not valid!"
            deleteDirectory()

    main()


#List users message boxes
def list_users_msg():
    global users_list, cid, pubkey
    nid = 0

    seqnumber = random.randint(0, 1500)
    
    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    r = raw_input("Would you like to insert a specific ID?(Y/N): ")
    while r != 'Y' and r != 'y' and r != 'N' and r != 'n':
        print("Wrong answer!\n")
        r = raw_input("Would you like to insert a specific ID?(Y/N): ")

    if r == 'Y' or r == 'y':
        nid = raw_input("Insert ID: ")
        lista = {'type' : 'list', 'sn': seqnumber, 'id' : nid}
    else:
        lista = {'type' : 'list', 'sn': seqnumber}

    # sign sn to send to server
    print "Signing %s to send to server" % lista
    userSignMessage('sn', lista)

    msg_mac = encapsulate_msg(lista)

    client_socket.send(json.dumps(msg_mac) + "\r\n")

    while True:
        rec = client_socket.recv(BUFSIZE)
        if rec is not None:
            data = json.loads(rec)

            if isinstance(data, dict):
                break

    if not data['type'] == 'secure':
        print "Invalid message from server!"

    if not set({'type', 'payload', 'hmac'}).issubset(set(data.keys())):
        print "Invalid message format from server"

    payload = data['payload']

    p = base64.decodestring(payload)

    j = ast.literal_eval(p)

    print "Received %s from server" % j

    if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber + 1:
        # check if hmac is correct
        if verify_HMAC(data):
            if set({'error', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                if valid_sig:
                    print "ERROR: ", j['error']
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            elif set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'],j['sn'], j['sign'], j['datetime'])
                if valid_sig:
                    lista = j['result']
                    users_list = {}
                    if nid == 0:
                        for coiso in lista:
                            users_list[str(coiso.keys()[0])] = coiso[str(coiso.keys()[0])]
                    else:
                        for coiso in lista:
                            users_list[str(coiso[str(coiso.keys()[1])])] = coiso[str(coiso.keys()[0])]

                    print users_list

                    if set(users_list.keys()).issuperset(set({str(cid)})):
                        if set(users_list[str(cid)].keys()).issuperset(set({'pubkey'})):
                            pubkey = base64.decodestring(users_list[str(cid)]['pubkey'])
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            else:
                print "Message is not in the expected format"
        else:
            print "\nMessage does not match to HMAC"
            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
            client_socket.close()
            connectToServer()
    else:
        print "\nSequence number is not valid!"

    main()

#New messages
def new_msg():
    global cid

    seqnumber = random.randint(0, 1500)

    if cid == -1:
        print "\nWrong client ID! Please, create a message or resquest id!"
        main()

    newmsg = {'type' : 'new', 'sn': seqnumber, 'id' : cid}

    # sign id to send to server
    print "Signing %s to send to server" % newmsg
    userSignMessage('id', newmsg)

    msg_mac = encapsulate_msg(newmsg)

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

    j = ast.literal_eval(p)

    print "Received %s from server" % j

    if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber + 1:
        # check if hmac is correct
        if verify_HMAC(data):
            if set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['sn'], j['sign'], j['datetime'])
                if valid_sig:
                    newmsglist = j['result']
                    print "List: ", newmsglist
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            elif set({'error', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                if valid_sig:
                    print "ERROR: ", j['error']
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            else:
                print "Message was not in the expected format"
        else:
            print "\nMessage does not match to HMAC"
            print "Signature is not correct!"
            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
            client_socket.close()
            connectToServer()
    else:
        print "\nSequence number is not valid!"

    main()

#All new messages
def new_all_msg():
    global cid, allmsglist

    seqnumber = random.randint(0, 1500)

    if cid == -1:
        print "\nWrong client ID! Please, create a message or resquest id!"
        main()

    allmsg = {'type' : 'all', 'sn': seqnumber, 'id' : cid}

    # sign id to send to server
    print "Signing %s to send to server" % allmsg
    userSignMessage('id', allmsg)

    msg_mac = encapsulate_msg(allmsg)

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

    j = ast.literal_eval(p)

    print "Received %s from server" % j

    if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber+1:
        # check if hmac is correct
        if verify_HMAC(data):
            if set({'error', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                if valid_sig:
                    print "ERROR: ", j['error']
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            elif set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                    # verify if signature is valid
                    valid_sig = validateServerSig(j['cert'], j['sn'], j['sign'], j['datetime'])
                    if valid_sig:
                        allmsglist = j['result']
                        print "All messages: ", allmsglist
                    else:
                        print "Signature is not correct!"
                        print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                        client_socket.close()
                        connectToServer()
            else:
                print "Message was not in the expected format"
        else:
            print "Message does not match to HMAC"
            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
            client_socket.close()
            connectToServer()
    else:
        print "\nSequence number is not valid!"

    main()

#Send message
def send_msg():
    global cid, K, users_list

    seqnumber = random.randint(0, 1500)

    if K == -1:
        print "\nWrong Session Key! Please, try a new connection!"
        main()

    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    if users_list == {}:
        print "\nPlease, choose first \"3 - List users messages boxes\""
        main()

    while True:
        dstid = raw_input("\nInsert destination ID: ")
        
        if set(users_list.keys()).issuperset(set({str(dstid)})):
            break
        else:
            print "\nNot enough information to send a message to client %s" %dstid
            print "\nPlease, choose first \"3 - List users messages boxes\""
            main()

    txt = raw_input("Message: ")
    
    aes = AESCipher(K)
    msg = aes.encrypt(txt)

    pubkey_dst = base64.decodestring(users_list[str(dstid)]['pubkey'])
    dst_cipher = RSACipher(None, pubkey_dst)

    msg_key = dst_cipher.encrypt_pub(aes.key)

    aes_copy = AESCipher(K)
    copy_msg = aes_copy.encrypt(txt)
    copy_key = dst_cipher.encrypt_pub(aes_copy.key)

    sendmsg = {'type' : 'send', 'sn': seqnumber, 'src' : cid, 'dst' : dstid, 'msg' : msg, 'copy' : copy_msg, 'msgkey' : msg_key, 'copykey' : copy_key}

    # sign msg to send to server
    print "Signing %s to send to server" % sendmsg
    userSignMessage('msg', sendmsg)

    msg_mac = encapsulate_msg(sendmsg)

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

    j = ast.literal_eval(p)

    print "Received %s from server" % j

    if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber+1:
        # check if hmac is correct
        if verify_HMAC(data):
            if set({'error','cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                if valid_sig:
                    print "ERROR: ", j['error']
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            elif set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                    # verify if signature is valid
                    valid_sig = validateServerSig(j['cert'], j['sn'], j['sign'], j['datetime'])
                    if valid_sig:
                        print "\nSent message successfully!"
                        print "Message ID: ", j['result'][0]
                        print "Receipt ID: ", j['result'][1]
                    else:
                        print "Signature is not correct!"
                        print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                        client_socket.close()
                        connectToServer()
            else:
                print "Message was not in the expected format"
        else:
            print "Message does not match to HMAC"
            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
            client_socket.close()
            connectToServer()
    else:
        print "\nSequence number is not valid!"

    main()

#Receive nessage from a user message box
def recv_msg_from_mb():
    global cid, rsa, allmsglist, password

    seqnumber = random.randint(0, 1500)

    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    if rsa == None:
        while True:
            password = getpass.getpass("Insert your password to read your keys: ")
        
            if password == "":
                print "\nWrong password! Password is empty!" 
            else:
                break
                
        read_keys(password)

    while True:
        msgid = raw_input("\nInsert message ID: ")
        
        pattern = "_?[0-9]+_[0-9]+"
        matches = re.match(pattern, msgid)
        
        if not matches:
            print "\nWrong format message ID!"
            print "Format: \"_Number_Number\" or \"Number_Number\""
        else:
            break

    recvmsg = {'type' : 'recv', 'sn': seqnumber, 'id' : cid, 'msg' : msgid}

    # sign msg to send to server
    print "Signing %s to send to server" % recvmsg
    userSignMessage('msg', recvmsg)

    msg_mac = encapsulate_msg(recvmsg)

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

    j = ast.literal_eval(p)

    print "Received %s from server" % j

    if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber+1:
        # check if hmac is correct
        if verify_HMAC(data):
            if set({'error','cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                if valid_sig:
                    print "\nERROR: ", j['error']
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            elif set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                    # verify if signature is valid
                    valid_sig = validateServerSig(j['cert'], j['sn'], j['sign'], j['datetime'])
                    if valid_sig:
                        recv = ast.literal_eval(j['result'][1])
                        msgrecv = AESCipher(None, rsa.decrypt_priv(recv['msgkey'])).decrypt(recv['msg'])
                        print "\nMessage received: ", msgrecv
                        # send receipt
                        send_receipt(json.dumps(j), msgid)
                    else:
                        print "Signature is not correct!"
                        print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                        client_socket.close()
                        connectToServer()
            else:
                print "Message was not in the correct format"
        else:
            print "Message does not match to HMAC"
            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
            client_socket.close()
            connectToServer()
    else:
        print "\nSequence number is not valid!"

    main()


#Send receipt for a message
def send_receipt(res, msgid):
    global cid

    seqnumber = random.randint(0, 1500)
    
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

    receiptmsg = {'type' : 'receipt', 'sn': seqnumber, 'id' : cid, 'msg' : msgid, 'receipt' : s, 'cert' : crypto.dump_certificate(crypto.FILETYPE_PEM, signCert), 'datetime' : dt.isoformat()}

    #sign receipt to send to server
    print "Signing %s to send to server" % receiptmsg
    userSignMessage('receipt', receiptmsg)

    msg_mac = encapsulate_msg(receiptmsg)

    client_socket.send(json.dumps(msg_mac) + "\r\n")

    print "\nReceipt sent successfully!"

#Status
def status():
    global cid

    seqnumber = random.randint(0, 1500)

    if cid == -1:
        print "\nWrong Client ID! Please, create a message or resquest id!"
        main()

    while True:
        msgid = raw_input("\nInsert message ID: ")
        
        pattern = "[0-9]+_[0-9]+"
        matches = re.match(pattern, msgid)
        
        if not matches:
            print "\nWrong format message ID!"
            print "Format: \"Number_Number\""
        else:
            break

    statmsg = {'type' : 'status', 'sn': seqnumber, 'id' : cid, 'msg' : msgid}

    # sign id to send to server
    print "Signing %s to send to server" % statmsg
    userSignMessage('id', statmsg)

    msg_mac = encapsulate_msg(statmsg)

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

    j = ast.literal_eval(p)

    print "Received %s from server" % j

    if set({'sn'}).issubset(set(j.keys())) and j['sn'] == seqnumber+1:
        if "error" in j.keys():
            print "\nERROR: ", j['error']
        # check if hmac is correct
        if verify_HMAC(data):
            if set({'error', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                # verify if signature is valid
                valid_sig = validateServerSig(j['cert'], j['error'], j['sign'], j['datetime'])
                if valid_sig:
                    print "\nERROR: ", j['error']
                else:
                    print "Signature is not correct!"
                    print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                    client_socket.close()
                    connectToServer()
            elif set({'result', 'cert', 'sign', 'datetime'}).issubset(set(j.keys())):
                    # verify if signature is valid
                    valid_sig = validateServerSig(j['cert'], j['sn'], j['sign'], j['datetime'])
                    if valid_sig:
                        for i in j['result']['receipts']:
                            # verificar se msgid e igual ao id no result
                            #if i['id'] == msgid[0]:
                            print "\n", i['id']
                    else:
                        print "Signature is not correct!"
                        print "\nCommunication may be compromised.\nClosing connection and opening a new one."
                        client_socket.close()
                        connectToServer()
            else:
                print "Message was not in the expected format"
        else:
            print "Message does not match to HMAC"
            print "\nCommunication may be compromised.\nClosing connection and opening a new one."
            client_socket.close()
            connectToServer()
    else:
        print "\nSequence number is not valid!" 

    main()

def exit():
    sys.exit('\n***Client closed by your order')

def create_directory():
    global directory

    n = os.getcwd() + "/" + client_name.lower() + "/"
    directory = os.path.dirname(n)

    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError as e:
            log(logging.ERROR, str(e.errno))

def existsDirectory():
    global directory
    
    filename = directory + "/privkey.txt.enc"
    if os.path.exists(filename):
        return True
    return False

def deleteDirectory():
    global directory

    filename = directory + "/privkey.txt.enc"
    os.remove(filename)
    os.rmdir(directory)

def read_keys(password):
    global pubkey, rsa

    filename1 = directory + "/privkey.txt.enc"

    if os.path.exists(filename1):

        # encrypt file
        res_pth = decrypt_file(filename1, key=password)
        os.remove(filename1)
        
        try:
            file = open(filename1[:-4], 'r+')
            privkey = file.read()
            rsa = RSACipher(privkey, None)
        except OSError as e:
            log(logging.ERROR, str(e.errno))

        file.close()

        # decrypt file
        encrypt_file(filename1[:-4], key=password)
        os.remove(filename1[:-4]) 

    else:
        rsa = RSACipher(None, None)
        (privkey, pubkey) = rsa.create_asymmetric_key()
        rsa.privkey = privkey
        rsa.pubkey = pubkey
        #print "Public Key: %s" % pubkey
        
        save_key(privkey, filename1[:-4])
        
        #encrypt file
        encrypt_file(filename1[:-4], key=password)
        os.remove(filename1[:-4]) 


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
    h = hmac.new(hashlib.sha256(str(K)).digest(), '', hashlib.sha1)
    h.update(msg64)

    # send encapsulated msg
    return {'type': 'secure', 'payload': msg64, 'hmac': base64.encodestring(h.hexdigest())}

def verify_HMAC(data):
    global K
    # check if hmac is correct
    h = hmac.new(hashlib.sha256(str(K)).digest(), '', hashlib.sha1)
    h.update(data['payload'])

    if hmac.compare_digest(base64.decodestring(data['hmac']), h.hexdigest()):
        return True
    else:
        return False

#Begin
try:
    print "Welcome!!"
    client_name = raw_input('\nPlease, insert your name: ')
    connectToServer()
    main()
except KeyboardInterrupt:
    pass
#.....