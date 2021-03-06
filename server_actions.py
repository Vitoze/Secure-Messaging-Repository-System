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
import datetime
import hmac
import base64
from smartcards import *

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
            'dh': self.processDH,
            'request': self.processRequest
        }

        self.registry = ServerRegistry()

    def handleRequest(self, s, request, client, privkey, server_cert):
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

            #significa que ainda nao se estabeleceu a chave de sessao
            if req['type'] == 'dh':
                    self.messageTypes[req['type']](req, client, privkey, server_cert)
            else:
                if not req['type'] == 'secure':
                    log(logging.ERROR, "Invalid message format from client")
                    return

                if not set({'type', 'payload', 'hmac'}).issubset(set(req.keys())):
                    log(logging.ERROR, "Insecure message from %s!" % client)
                    # sign error msg to send to client
                    error_msg = {"error": "Please ensure your message autentication and integrity"}
                    serverSignMessage(server_cert, privkey, 'error', error_msg)
                    client.sendResult(self.encapsulate_msg(error_msg, client))
                    return

                info = None
                data = None

                try:
                    info = base64.decodestring(req['payload'])
                    data = json.loads(info)
                except:
                    log(logging.ERROR, "Invalid field type from client")
                    # sign error msg to send to client
                    error_msg = {"error": "payload can not be processed", "sn": data['sn'] + 1}
                    serverSignMessage(server_cert, privkey, 'error', error_msg)
                    client.sendResult(self.encapsulate_msg(error_msg, client))
                    return

                #check if hmac is correct
                h = hmac.new(hashlib.sha256(str(client.skey)).digest(), '', hashlib.sha1)
                h.update(req['payload'])

                d = base64.decodestring(req['hmac'])

                if hmac.compare_digest(base64.decodestring(req['hmac']), h.hexdigest()):
                    # process message
                    if data['type'] in self.messageTypes:
                        self.messageTypes[data['type']](data, client, privkey, server_cert)
                    else:
                        log(logging.ERROR, "Invalid message type: " +
                            str(data['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                        # sign error msg to send to client
                        error_msg = {"error": "unknown request"}
                        serverSignMessage(server_cert, privkey, 'error', error_msg)
                        client.sendResult(self.encapsulate_msg(error_msg, client))
                else:
                    log(logging.ERROR, "Message Authentication from %s failed!" % client)
                    # sign error msg to send to client
                    error_msg = {"error": "Please ensure your message autentication and integrity"}
                    serverSignMessage(server_cert, privkey, 'error', error_msg)
                    client.sendResult(self.encapsulate_msg(error_msg, client))

        except Exception, e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid_cert' not in data.keys():
            log(logging.ERROR, "No \"uuid\" certificate in \"create\" message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if authentication certificate correspond to client
        #crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_pem())
        uuid_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['uuid_cert'])
        if uuid_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Authentication certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {
                "error": "Authentication certificate does not correspond to client associated to this socket",
                "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        #print uuid_cert.get_subject().__getattr__('CN')
        uuid = self.calculateUuid(data['uuid_cert'])
        #print type(uuid)
        #print uuid

        if self.registry.uuidExists(uuid):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "uuid already exists", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['uuid_cert'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        me = self.registry.addUser(data, base64.encodestring(uuid))

        msg = {"result": me.id, "sn": data['sn']+1}

        # sign result to send to client
        serverSignMessage(server_cert, privkey, 'result', msg)

        logging.info("Send %s to %s" % (msg, client))

        client.sendResult(self.encapsulate_msg(msg, client))
        client.id = me.id

    def processList(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user
            if not self.registry.userExists(user):
                log(logging.ERROR,"Unknown id: " + json.dumps(data))
                # sign error msg to send to client
                error_msg = {"error": "Unknown id", "sn": data['sn']+1}
                serverSignMessage(server_cert, privkey, 'error', error_msg)
                client.sendResult(self.encapsulate_msg(error_msg, client))
                return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['sn'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        msg = {"result": userList, "sn": data['sn']+1}

        logging.info("Send %s to %s" % (msg, client))

        # sign result to send to client
        serverSignMessage(server_cert, privkey, 'sn', msg)

        logging.info("Send %s to %s" % (msg, client))

        client.sendResult(self.encapsulate_msg(msg, client))

    def processNew(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not client.id == user:
            log(logging.ERROR,
                "Wrong client id for \"new\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "Your client id is not correct!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['id'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        msg = {"result":  self.registry.userNewMessages(user), "sn": data['sn']+1}

        logging.info("Send %r to %s" % (client, msg))

        # sign result to send to client
        serverSignMessage(server_cert, privkey,'sn', msg)

        client.sendResult(self.encapsulate_msg(msg, client))

    def processAll(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not client.id == user:
            log(logging.ERROR,
                "Wrong client id for \"new\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "Your client id is not correct!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['id'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        msg = {"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)], "sn": data['sn']+1}

        logging.info("Send %r to %s" % (client, msg))

        # sign result to send to client
        serverSignMessage(server_cert, privkey, 'sn', msg)

        client.sendResult(self.encapsulate_msg(msg, client))

    def processSend(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy', 'msgkey', 'copykey'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = json.dumps({'msg' : data['msg'], 'msgkey' : data['msgkey']})
        copy = json.dumps({'copy' : data['copy'], 'copykey' : data['copykey']})

        if not client.id == srcId:
            log(logging.ERROR,
                "Wrong client id for \"send\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "Your client id is not correct!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong parameters", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong parameters", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if srcId == dstId:
            log(logging.ERROR,
                "Wrong client id for \"send\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "You can not send a message for yourself!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return


        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['msg'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # Save message and copy
        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        msg = {"result": response, "sn": data['sn']+1}

        logging.info("Send %r to %s" % (client, msg))

        # sign result to send to client
        serverSignMessage(server_cert, privkey, 'sn', msg)

        client.sendResult(self.encapsulate_msg(msg, client))

    def processRecv(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not client.id == fromId:
            log(logging.ERROR,
                "Wrong client id for \"recv\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "Your client id is not correct!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong parameters", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong parameters", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['msg'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        msg = {"result": response, "sn": data['sn']+1}

        logging.info("Send %s to %s" % (msg, client))

        # sign result to send to client
        serverSignMessage(server_cert, privkey, 'sn', msg)

        client.sendResult(self.encapsulate_msg(msg, client))

    def processReceipt(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt', 'cert', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong request format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not client.id == fromId:
            log(logging.ERROR,
                "Wrong client id for \"receipt\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "Your client id is not correct!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong parameters", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['sn'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return
        
        fromId = int(data['id'])
        msg = str(data["msg"])

        if not client.id == fromId:
            log(logging.ERROR,
                "Wrong client id for \"status\" message: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "Your client id is not correct!", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        if not self.registry.copyExists(fromId, msg):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong parameters", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['id'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # Read message

        response = self.registry.getReceipts(fromId, msg)

        msg = {"result": response, "sn": data['sn']+1}

        logging.info("Send %r to %s" % (client, msg))

        # sign result to send to client
        serverSignMessage(server_cert, privkey, 'sn', msg)

        client.sendResult(self.encapsulate_msg(msg, client))

    def processDH(self, data, client, privkey, server_cert):
        log(logging.DEBUG, "%s" % json.dumps(data))

        #verificar se a mensagem esta no formato correto
        if set({'B', 'sign', 'cert', 'datetime'}).issubset(set(data.keys())):
            valid_sig = validateUserSig(data['cert'], data['B'], data['sign'], data['datetime'])
            if not valid_sig:
                log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
                # sign error msg to send to client
                error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
                serverSignMessage(server_cert, privkey, 'error', error_msg)
                client.sendResult(error_msg, client)
                return

            msg_ok = {'ok' : "not ok"}

            #verificar se B e um inteiro
            if isinstance(data['B'], int):
                #verificar se B nao e nulo
                if data['B'] != 0:
                    try:
                        #Calcular K = B^a mod p
                        client.skey = (data['B']**client.a)%client.p
                        msg_ok = {'ok': "ok", 'sn': data['sn'] + 1}
                    except:
                        msg_ok = {'ok': "not ok", 'sn': data['sn'] + 1}

            # sign uuid to send to user
            serverSignMessage(server_cert, privkey, 'ok', msg_ok)

            client.sendResult(msg_ok)

        #fim do processo diffie-hellman
        elif set({'ok', 'sign', 'cert', 'datetime'}).issubset(set(data.keys())):
            valid_sig = validateUserSig(data['cert'], data['ok'], data['sign'], data['datetime'])
            if not valid_sig:
                log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
                # sign error msg to send to client
                error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
                serverSignMessage(server_cert, privkey, 'error', error_msg)
                client.sendResult(error_msg, client)
                return

            if data['ok'] == "ok":
                logging.info("Session Key established")
                server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
                client.name = server_cert.get_subject().__getattr__('CN')
            else:
                logging.info("Session Key not established")
        else:
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format"}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(error_msg)

    def processRequest(self, data, client, privkey, server_cert):

        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid_cert' not in data.keys():
            log(logging.ERROR, "No \"uuid\" certificate in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "wrong message format", "sn": data['sn']+1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        if not set({'cert', 'sign', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "No signature field in message: " +
                json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature is missing", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        # verify if signature certificate correspond to client
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
        if client_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {"error": "Certificate does not correspond to client associated to this socket",
                         "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if signature is valid
        valid_sig = validateUserSig(data['cert'], data['uuid_cert'], data['sign'], data['datetime'])
        if not valid_sig:
            log(logging.ERROR, "Signature is not correct: " + json.dumps(data))
            # sign error msg to send to client
            error_msg = {"error": "signature does not match", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        # verify if authentication certificate correspond to client
        uuid_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['uuid_cert'])
        if uuid_cert.get_subject().__getattr__('CN') != client.name:
            log(logging.ERROR, "Authentication certificate does not correspond to client associated to this socket")
            # sign error msg to send to client
            error_msg = {
                "error": "Authentication certificate does not correspond to client associated to this socket",
                "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            # closing connection to client
            log(logging.ERROR, "Connection may be compromised. Closing connection.")
            client.socket.close()
            return

        uuid = self.calculateUuid(data['uuid_cert'])

        if self.registry.uuidExists(base64.encodestring(uuid)):
            client.id = self.registry.getUserId(base64.encodestring(uuid))
        else:
            log(logging.ERROR, "Uuid does not exists")
            # sign error msg to send to client
            error_msg = {"error": "uuid does not exists", "sn": data['sn'] + 1}
            serverSignMessage(server_cert, privkey, 'error', error_msg)
            client.sendResult(self.encapsulate_msg(error_msg, client))
            return

        msg = {'id': client.id, "sn": data['sn']+1}

        # sign id to send to user
        serverSignMessage(server_cert, privkey, 'id', msg)

        logging.info("Send %r to %s" % (client, msg))

        client.sendResult(self.encapsulate_msg(msg, client))

    def calculateUuid(self, cert_uuid):
        uuid = None
        if cert_uuid is not None:
            try:
                uuid = hashlib.sha256(cert_uuid).digest()
            except Exception as e:
                print e
        return uuid

    def encapsulate_msg(self, msg, client):
        # convert msg to base64
        msg64 = base64.encodestring(json.dumps(msg))

        # calcular hmac
        h = hmac.new(hashlib.sha256(str(client.skey)).digest(), '', hashlib.sha1)
        h.update(msg64)

        # send encapsulated msg
        return {'type': 'secure', 'payload': msg64, 'hmac': base64.encodestring(h.hexdigest())}
        