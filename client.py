from socket import *
from select import *
import json
import sys
import time
import logging
import ast


#variable initialization
BUFSIZE = 512 * 1024
client_socket = socket(AF_INET, SOCK_STREAM)

print 'Connecting to server...'
client_socket.connect(('127.0.0.1', 8080))
client_socket.send('Hello Server')
client_socket.close()
