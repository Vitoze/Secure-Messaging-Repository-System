import os
import sys
from log import *
import logging
import re
import json
import time
from OpenSSL import crypto

sys.tracebacklimit = 30

MBOXES_PATH = "mboxes"
RECEIPTS_PATH = "receipts"
DESC_FILENAME = "description"


class UserDescription(dict):

    def __init__(self, uid, description=None):
        dict.__init__(self, id=uid, description=description)
        self.id = uid
        self.description = description


class ServerRegistry:

    def __init__(self):

        self.users = {}

        for dirname in [MBOXES_PATH, RECEIPTS_PATH]:
            try:
                if not os.path.exists(dirname):
                    logging.debug("Creating " + dirname)
                    os.mkdir(dirname)
            except:
                logging.exception("Cannot create directory " + dirname)
                sys.exit(1)

        for entryname in os.listdir(MBOXES_PATH):
            logging.info("Found " + entryname)

            if os.path.isdir(os.path.join(MBOXES_PATH, entryname)):
                uid = 0
                try:
                    uid = int(entryname)
                except:
                    continue

                logging.info("Loading " + entryname)

                path = os.path.join(MBOXES_PATH, entryname, DESC_FILENAME)

                description = None
                try:
                    with open(path) as f:
                        description = json.loads(f.read())
                except:
                    logging.exception(
                        "Cannot load user description from " + path)
                    sys.exit(1)

                self.users[uid] = UserDescription(uid , description)

    def saveOnFile(self, path, data):
        with open(path, "w") as f:
            f.write(data)

    def readFromFile(self, path):
        log(logging.DEBUG, "Read from file: " + path)
        with open(path, "r") as f:
            return f.read()

    def messageWasRed(self, uid, msg):
        msg = str(msg)

        if msg.startswith("_"):
            return os.path.exists(os.path.join(self.userMessageBox(uid), msg))
        else:
            return os.path.exists(os.path.join(self.userMessageBox(uid), "_" + msg))

    def messageExists(self, uid, message):
        return os.path.exists(os.path.join(self.userMessageBox(uid), message))

    def copyExists(self, uid, message):
        return os.path.exists(os.path.join(self.userReceiptBox(uid), message))

    def userExists(self, uid):
        return self.getUser(uid) is not None

    def uuidExists(self, uuid):
        for entryname in os.listdir(MBOXES_PATH):

            if os.path.isdir(os.path.join(MBOXES_PATH, entryname)):
                uid = 0
                try:
                    uid = int(entryname)
                except:
                    continue

                path = os.path.join(MBOXES_PATH, entryname, DESC_FILENAME)

                description = None
                try:
                    with open(path) as f:
                        description = json.loads(f.read())
                except:
                    logging.exception(
                        "Cannot load user description from " + path)
                    sys.exit(1)
                print type(description['uuid'])
                print type(uuid)
                if description['uuid'] == uuid:
                    return True
        return False

    def getUserId(self, uuid):
        for entryname in os.listdir(MBOXES_PATH):

            if os.path.isdir(os.path.join(MBOXES_PATH, entryname)):
                uid = 0
                try:
                    uid = int(entryname)
                except:
                    continue

                path = os.path.join(MBOXES_PATH, entryname, DESC_FILENAME)

                description = None
                try:
                    with open(path) as f:
                        description = json.loads(f.read())
                except:
                    logging.exception(
                        "Cannot load user description from " + path)
                    sys.exit(1)

                if description['uuid'] == uuid:
                    return uid
        return 0

    def getUser(self, uid):
        if isinstance(uid, int):
            if uid in self.users.keys():
                return self.users[uid]
            return None

        if isinstance(uid, str):
            for user in self.users:
                if user.id == uid:
                    return user
        return None

    def getUserSN(self, uid):
        for entryname in os.listdir(MBOXES_PATH):

            if os.path.isdir(os.path.join(MBOXES_PATH, entryname)):
                uid = 0
                try:
                    uid = int(entryname)
                except:
                    continue

                path = os.path.join(MBOXES_PATH, entryname, DESC_FILENAME)

                description = None
                try:
                    with open(path) as f:
                        description = json.loads(f.read())
                except:
                    logging.exception(
                        "Cannot load user description from " + path)
                    sys.exit(1)
                return description['serial_n']
        return None

    def addUser(self, description, uuid):
        uid = 1

        #get last id created
        while self.userExists(uid):
            uid += 1

        if 'type' in description.keys():
            del description['type']

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, description['uuid_cert'])
        sn = cert.get_serial_number()
        d = {}
        d['serial_n'] = sn
        d['uuid'] = uuid
        d['pubkey'] = description['pubkey']

        log(logging.DEBUG, "add user \"%s\": %s" % (uid, d))

        user = UserDescription(uid, d)
        self.users[uid] = user

        for path in [self.userMessageBox(uid), self.userReceiptBox(uid)]:
            try:
                os.mkdir(path)
            except:
                logging.exception("Cannot create directory " + path)
                sys.exit(1)

        path = ""
        try:
            path = os.path.join(MBOXES_PATH, str(uid), DESC_FILENAME)
            log(logging.DEBUG, "add user description " + path)
            
            self.saveOnFile(path, json.dumps(d))
        except:
            logging.exception("Cannot create description file " + path)
            sys.exit(1)

        return user

    def listUsers(self, uid):
        if uid == 0:
            log(logging.DEBUG, "Looking for all connected users")
        else:
            log(logging.DEBUG, "Looking for \"%d\"" % uid)

        if uid != 0:
            user = self.getUser(uid)

            if user is not None:
                return [user]
            return None

        userList = []
        for k in self.users.keys():
            userList.append({self.users[k].id : self.users[k].description})

        return userList

    def userAllMessages(self, uid):
        return self.userMessages(self.userMessageBox(uid), "_?[0-9]+_[0-9]+")

    def userNewMessages(self, uid):
        return self.userMessages(self.userMessageBox(uid), "[0-9]+_[0-9]+")

    def userSentMessages(self, uid):
        return self.userMessages(self.userReceiptBox(uid), "[0-9]+_[0-9]+")

    def userMessages(self, path, pattern):
        log(logging.DEBUG, "Look for files at " +
            path + " with pattern " + pattern)

        messageList = []
        if not os.path.exists(path):
            return []

        try:
            for filename in os.listdir(path):
                log(logging.DEBUG, "\tFound file " + filename)
                if re.match(pattern, filename):
                    messageList.append(filename)
        except:
            logging.exception(
                "Error while listing messages in directory " + path)

        return messageList

    def newFile(self, basename):
        i = 1
        while True:
            path = os.path.join(basename, str(i))
            if not os.path.exists(path):
                return str(i)

            i += 1

    def sendMessage(self, src, dst, msg, receipt):
        nr = "0"
        src = str(src)
        dst = str(dst)

        try:
            path = os.path.join(self.userMessageBox(dst), src + "_")
            nr = self.newFile(path)
            self.saveOnFile(path + nr, msg)

            result = [src + "_" + nr]
            path = os.path.join(self.userReceiptBox(src), dst + "_")
            self.saveOnFile(path + nr, receipt)
        except:
            logging.exception(
                "Cannot create message or receipt file " + path + nr)
            return ["", ""]

        result.append(dst + "_" + nr)
        return result

    def readMsgFile(self, uid, msg):
        path = self.userMessageBox(uid)

        if msg.startswith('_'):
            path = os.path.join(path, msg)
        else:
            try:
                f = os.path.join(path, msg)
                path = os.path.join(path, "_" + msg)
                log(logging.DEBUG, "Marking message " + msg + " as read")
                print f
                print path
                os.rename(f, path)
            except:
                logging.exception("Cannot rename message file to " + path)
                path = os.path.join(self.userMessageBox(str(uid)), msg)

        return self.readFromFile(path)

    def recvMessage(self, uid, msg):
        uid = str(uid)
        msg = str(msg)

        result = []
        pattern = "_?([0-9]+)_[0-9]+"

        matches = re.match(pattern, msg)
        if not matches:
            log(logging.ERROR,
                "Internal error, wrong message file name format!")
            sys.exit(2)

        result.extend(matches.group(1))

        try:
            result.append(self.readMsgFile(uid, msg))
        except:
            logging.exception("Cannot read message " +
                              msg + " from user " + uid)

        return result

    def userMessageBox(self, uid):
        return os.path.join(MBOXES_PATH, str(uid))

    def userReceiptBox(self, uid):
        return os.path.join(RECEIPTS_PATH, str(uid))

    def storeReceipt(self, uid, msg, receipt):
        pattern = re.compile("_?([0-9]+)_([0-9])")
        m = pattern.match(msg)

        if not m:
            log(logging.ERROR,
                "Internal error, wrong message file name (" + msg + ") format!")
            sys.exit(2)

        print "\n\n\n\n\n"
        print time.time()
        print "\n\n\n\n\n"
        path = self.userReceiptBox(os.path.join(m.group(1), "_%s_%s_%d" % (uid, m.group(2), time.time() * 1000)))

        try:
            self.saveOnFile(path, receipt)
        except:
            logging.exception("Cannot create receipt file " + path)

    def getReceipts(self, uid, msg):

        pattern = re.compile("_(([0-9])+_[0-9])_([0-9]+)")
        boxdir = self.userReceiptBox(uid)
        result = {}
        copy = ""

        try:
            path = os.path.join(self.userReceiptBox(uid), msg)
            copy = self.readFromFile(path)
        except:
            logging.exception("Cannot read a copy file")
            copy = ""

        result = {"msg": copy, "receipts": []}

        for fname in os.listdir(boxdir):
            print fname
            m = pattern.match(fname)
            if m and m.group(1) == msg:
                path = os.path.join(self.userReceiptBox(uid), fname)
                try:
                    receiptText = self.readFromFile(path)
                except:
                    logging.exception("Cannot read a receipt file")
                    receiptText = ""

                receipt = {
                    "date": m.group(3), "id": m.group(2), "receipt": receiptText}
                result['receipts'].append(receipt)

        return result
