from socket import *
from select import *
import json
import sys
import time
import logging
import ast

#variable initialization
BUFSIZE = 512 * 1024
client_name = ''

def connectToServer():
    global client_socket
    client_socket = socket(AF_INET, SOCK_STREAM)
    #global client_name
    #client_name = raw_input('Please, insert your name: ')
    # Conection
    print 'Connecting to server...'
    client_socket.connect(('127.0.0.1', 8080))

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
    msg = {'type' : 'create', 'uuid' : 4}   # uuid???
    client_socket.send(json.dumps(msg) + "\r\n")
    data = client_socket.recv(BUFSIZE)
    print data
    main()

#List users message boxes
def list_users_msg():
    list = {'type' : 'list'}
    client_socket.send(json.dumps(list) + "\r\n")
    lst = client_socket.recv(BUFSIZE)
    print lst
    main()

#New messages
def new_msg():
    newmsg = {'type' : 'new', 'id' : 1}
    client_socket.send(json.dumps(newmsg) + "\r\n")
    newmsglst = client_socket.recv(BUFSIZE)
    print newmsglst
    main()

#All new messages
def new_all_msg():
    allmsg = {'type' : 'all', 'id' : 1}
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
    recvmsg = {'type' : 'recv', 'id' : 1, 'msg' : 1}
    client_socket.send(json.dumps(recvmsg) + "\r\n")
    recvmsglst = client_socket.recv(BUFSIZE)
    print recvmsglst
    main()


#Send receipt for a message
def send_receipt():
    receiptmsg = {'type' : 'receipt', 'id' : 1, 'msg' : 1, 'receipt' : ''}
    client_socket.send(json.dumps(receiptmsg) + "\r\n")
    receiptmsglst = client_socket.recv(BUFSIZE)
    print receiptmsglst
    main()

#Status
def status():
    statmsg = {'type' : 'status', 'id' : 1, 'msg' : 1}
    client_socket.send(json.dumps(statmsg) + "\r\n")
    statmsglst = client_socket.recv(BUFSIZE)
    print statmsglst
    main()

def exit():
    sys.exit('\n***Client closed by your order')

#Begin
try:
    print "Welcome!!"
    connectToServer()
    main()
except KeyboardInterrupt:
    pass
#.....