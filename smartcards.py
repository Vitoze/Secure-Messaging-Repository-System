import M2Crypto
import PyKCS11
import sys
from OpenSSL import crypto
from log import *

slot = None
lib = "/usr/local/lib/libpteidpkcs11.so"

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

def detectCardReader():

    slots = pkcs11.getSlotList()

    if len(slots) != 0:
        slot =  slots[0]

    return slot


def getCertificate(label):
    cert=None
    slot = detectCardReader()
    if slot is not None:
        try:
            session = pkcs11.openSession(slot)
            objs = session.findObjects(template=(
                (PyKCS11.CKA_LABEL, label),
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)))
            der = ''.join(chr(c) for c in objs[0].to_dict()['CKA_VALUE'])
            cert = M2Crypto.X509.load_cert_string(der, M2Crypto.X509.FORMAT_DER)
            session.closeSession()
        except OSError as e:
            log(logging.ERROR, str(e.errno))
    return cert

def getCCPrivKey(label):
    key = None
    slot = detectCardReader()
    if slot is not None:
        try:
            session = pkcs11.openSession(slot)
            key = session.findObjects(template=((PyKCS11.CKA_LABEL, label),
                                                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)))[0]
            session.closeSession()
        except OSError as e:
            log(logging.ERROR, str(e.errno))
    return key

def signWithCC(priv_key, data):
    slot = detectCardReader()
    result = ''
    if slot is not None:
        try:
            session = pkcs11.openSession(slot)
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
            sig = session.sign(priv_key, data, mech)
            result = ''.join(chr(c) for c in sig)
            session.closeSession()
        except OSError as e:
            log(logging.ERROR, str(e.errno))
    return result

