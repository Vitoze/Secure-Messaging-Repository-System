import logging
from log import *
from server_registry import *
from server_client import *
import json
from ciphers import *
import hashlib
import M2Crypto
from OpenSSL import crypto
from certificates import *

class ServerActions:
    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'dh': self.processDH
        }

        self.registry = ServerRegistry()

    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:

                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                log(logging.ERROR, "Message has no TYPE field")
                return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"})

        except Exception, e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        # Desencriptar conteudo uuid
        #rsa = RSACipher(client.skey, None, None)
        #print("\n\n\n\n")
        #print(rsa.decrypt_skey(data['uuid']))
        #print("\n\n\n\n")
        
        #uuid = int(rsa.decrypt_skey(data['uuid']))

        uuid = base64.decodestring(data['uuid'])

        '''
        if not isinstance(uuid, int):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return
        '''
        print type(uuid)
        if self.registry.userExists(uuid):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"})
            return

        me = self.registry.addUser(data)

        #client.sendResult({"result": rsa.encrypt_skey(str(me.id))})
        client.sendResult({"result": me.id})

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult({"result": userList})

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult(
            {"result": self.registry.userNewMessages(user)})

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult({"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]})

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'msg'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str(data['msg'])
        copy = str(data['copy'])

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult({"result": response})

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult({"result": response})

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"})

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
        
        fromId = int(data['id'])
        msg = str(data["msg"])

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error", "wrong parameters"})
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult({"result": response})

    def processDH(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        #verificar se a mensagem esta no formato correto
        if not set({'B', 'sign', 'cert', 'chain'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        # verify if signature is valid
        # data['cert'] value is a pem certificate
        #print data['cert']
        #print type(data['cert'])
        #coiso = str(data['cert'])
        #string = crypto.dump_certificate(crypto.FILETYPE_PEM, data['cert'])
        cert = M2Crypto.X509.load_cert_string(data['cert'])
        #cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        s = data['sign']
        print s
        print len(s)
        sig = base64.decodestring(s)
        '''
        valid_sig = crypto.verify(cert, sig, str(data['B']), "sha256")
        if valid_sig != None:
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "invalid signature"})
        '''

        pub_key = cert.get_pubkey()
        pub_key.verify_init()
        pub_key.verify_update(str(data['B']))
        valid_sig = pub_key.verify_final(sig)
        if valid_sig != 1:
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "invalid signature"})


        # verify if certificate is valid
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        chain = generateCertChain(certificate)
        valid_cert = verifyChain(chain, certificate)
        if valid_cert != None:
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "cannot validate cerfiticate with given certificate chain"})

        #verificar se B e um inteiro
        if isinstance(data['B'], int):
            #verificar se B nao e nulo
            if data['B'] != 0:
                #Calcular K = B^a mod p
                client.skey = (data['B']**client.a)%client.p
        logging.info("Session Key established")
