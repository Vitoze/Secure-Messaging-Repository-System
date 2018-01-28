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

            #significa que ainda nao se estabeleceu a chave de sessao
            if req['type'] == 'dh':
                if req['type'] in self.messageTypes:
                    self.messageTypes[req['type']](req, client)
                else:
                    log(logging.ERROR, "Invalid message type: " +
                        str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                    client.sendResult(self.encapsulate_msg({"error": "unknown request"}, client))
            else:
                if not req['type'] == 'secure':
                    log(logging.ERROR, "Invalid message format from client")
                    return

                if not set({'type', 'payload', 'hmac'}).issubset(set(req.keys())):
                    log(logging.ERROR, "Insecure message from %s!" % client)
                    client.sendResult(self.encapsulate_msg({"error": "Please ensure your message autentication and integrity"}, client))
                    return

                #try:
                info = base64.decodestring(req['payload'])
                data = json.loads(info)

                print client.skey
                print hashlib.sha256(str(client.skey)).digest()
                print hashlib.sha256(str(client.skey)).digest()
                print hashlib.sha256(str(client.skey)).digest()

                #check if hmac is correct
                h = hmac.new(hashlib.sha256(str(client.skey)).digest(), '', hashlib.sha1)
                h.update(req['payload'])

                d = base64.decodestring(req['hmac'])
                print "req['payload']"
                print req['payload']
                print "Digest Key"
                print hashlib.sha256(str(client.skey)).digest()
                print "h"
                print h
                print "req['hmac']"
                print req['hmac']
                print "d"
                print d

                print "Comparacao"
                print d == h.hexdigest()
                print hmac.compare_digest(d, h.hexdigest())

                if hmac.compare_digest(base64.decodestring(req['hmac']), h.hexdigest()):
                    # process message
                    if data['type'] in self.messageTypes:
                        self.messageTypes[data['type']](data, client)
                    else:
                        log(logging.ERROR, "Invalid message type: " +
                            str(data['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                        client.sendResult(self.encapsulate_msg({"error": "unknown request"}, client))
                else:
                    log(logging.ERROR, "Message Authentication from %s failed!" % client)
                    client.sendResult(self.encapsulate_msg({"error": "Please ensure your message autentication and integrity"}, client))
                '''
                except:
                    log(logging.ERROR, "Invalid field type from client")
                    return
                '''
        except Exception, e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))
            return

        #uuid = base64.decodestring(data['uuid'])

        '''
        if not isinstance(uuid, int):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return
        '''
        print type(data['uuid'])
        if self.registry.uuidExists(data['uuid']):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "uuid already exists"}, client))
            return

        me = self.registry.addUser(data)

        client.sendResult(self.encapsulate_msg({"result": me.id}, client))
        client.id = me.id

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult(self.encapsulate_msg({"result": userList}, client))

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))
            return

        if not client.id == user:
            log(logging.ERROR,
                "Wrong client id for \"new\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        client.sendResult(self.encapsulate_msg({"result":  self.registry.userNewMessages(user)}, client))

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))
            return

        if not client.id == user:
            log(logging.ERROR,
                "Wrong client id for \"new\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        client.sendResult(self.encapsulate_msg({"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]}, client))

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy', 'msgkey', 'copykey'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = json.dumps({'msg' : data['msg'], 'msgkey' : data['msgkey']})
        copy = json.dumps({'copy' : data['copy'], 'copykey' : data['copykey']})

        if not client.id == srcId:
            log(logging.ERROR,
                "Wrong client id for \"send\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult(self.encapsulate_msg({"result": response}, client))

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not client.id == fromId:
            log(logging.ERROR,
                "Wrong client id for \"recv\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult(self.encapsulate_mg({"result": response, "time" : datetime.datetime.now().isoformat()}, client))

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt', 'cert', 'datetime'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong request format"}, client))

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not client.id == fromId:
            log(logging.ERROR,
                "Wrong client id for \"receipt\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))
        
        fromId = int(data['id'])
        msg = str(data["msg"])

        if not client.id == fromId:
            log(logging.ERROR,
                "Wrong client id for \"status\" message: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong parameters"}, client))
            return

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error", "wrong parameters"}, client))
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult(self.encapsulate_msg({"result": response}, client))

    def processDH(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        #verificar se a mensagem esta no formato correto
        if set({'B', 'sign', 'cert', 'datetime'}).issubset(set(data.keys())):
            # verify if signature is valid
            # data['cert'] value is a pem certificate
            #print data['cert']
            #print type(data['cert'])
            #coiso = str(data['cert'])
            #string = crypto.dump_certificate(crypto.FILETYPE_PEM, data['cert'])
            #print data['cert']
            cert = M2Crypto.X509.load_cert_string(data['cert'])
            #cert = crypto.load_certificate(crypto.FILETYPE_PEM, data['cert'])
            s = data['sign']
            #print s
            #print len(s)
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

            # validate signature time
            date1 = datetime.datetime.strptime(certificate.get_notAfter(), '%Y%m%d%H%M%SZ')
            date2 = datetime.datetime.strptime(data['datetime'], '%Y-%m-%dT%H:%M:%S.%f')
            date3 = datetime.datetime.strptime(certificate.get_notBefore(), '%Y%m%d%H%M%SZ')
            if date1 <= date2:
                print "Invalid signature time"
            if date3 >= date2:
                print "Invalid signature time"

            msg_ok = {'ok' : "not ok"}

            #verificar se B e um inteiro
            if isinstance(data['B'], int):
                #verificar se B nao e nulo
                if data['B'] != 0:
                    try:
                        #Calcular K = B^a mod p
                        client.skey = (data['B']**client.a)%client.p
                        msg_ok = {'ok' : "ok"}
                    except:
                        msg_ok = {'ok' : "not ok"}

            client.sendResult(msg_ok)

        elif set({'ok'}).issubset(set(data.keys())):
            if data['ok'] == "ok":
                logging.info("Session Key established")
            else:
                logging.info("Session Key not established") #fechar o socket do user
        else:
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

    def processRequest(self, data, client):

        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult(self.encapsulate_msg({"error": "wrong message format"}, client))
            return

        if self.registry.uuidExists(data['uuid']):
            client.id = self.registry.getUserId(data['uuid'])

        msg = {'id' : client.id}

        client.sendResult(self.encapsulate_msg(msg, client))

    def encapsulate_msg(self, msg, client):
        # convert msg to base64
        msg64 = base64.encodestring(json.dumps(msg))

        # calcular hmac
        h = hmac.new(hashlib.sha256(str(client.skey)).digest(), '', hashlib.sha1)
        h.update(msg64)

        # send encapsulated msg
        return {'type': 'secure', 'payload': msg64, 'hmac': base64.encodestring(h.hexdigest())}
        