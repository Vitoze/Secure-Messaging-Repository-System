import M2Crypto
import PyKCS11
import sys
from OpenSSL import crypto
from log import *
import datetime
import base64
from certificates import *

slot = None
lib = "/usr/local/lib/libpteidpkcs11.so"

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

def detectCardReader():

    slots = pkcs11.getSlotList()

    if len(slots) != 0:
        slot =  slots[0]
    else:
        print "Please, insert your card in the card reader"
        exit()

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

def userSignMessage(field, msg):
    # get signature private key from CC
    private_key = getCCPrivKey("CITIZEN SIGNATURE KEY")

    # Assinar field para enviar ao servidor

    sig = signWithCC(private_key, str(msg[field]))
    dt = datetime.datetime.now()
    s = base64.encodestring(sig)

    # get citizen signature public key certificate
    pub_cert = getCertificate("CITIZEN SIGNATURE CERTIFICATE")
    signCert = crypto.load_certificate(crypto.FILETYPE_ASN1, pub_cert.as_der())

    msg['cert'] = crypto.dump_certificate(crypto.FILETYPE_PEM, signCert)
    msg['sign'] = s
    msg['datetime'] = dt.isoformat()

def serverSignMessage(cert, privkey, field, msg):
    signature = crypto.sign(privkey, str(msg[field]), "sha256")
    dt = datetime.datetime.now()
    s = base64.encodestring(signature)

    msg['sign'] = s
    msg['datetime'] = dt.isoformat()
    msg['cert'] = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)


def validateServerSig(cert, field, sig, dt):

    print "Validations:"
    print " - Validating signature..."
    c = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    s = sig
    sig = base64.decodestring(s)
    try:
        valid_sig = crypto.verify(c, sig, str(field), "sha256")
        print "...OK!"
    except:
        return False

    # validate signature time
    sigtime_isValid = validateSigTime(c, dt)

    if not sigtime_isValid:
        print "Invalid signature time"
        return False

    # verify if certificate is valid
    print " - Validating certificate and certificate chain..."
    #print c.get_subject()
    (is_valid, motive) =  validateCertificate(c)
    if not is_valid:
        print "Certificate is not valid: %s" % motive
        return False
    print "...OK!"
    return True

def validateUserSig(cert, field, sig, dt):
    cert = M2Crypto.X509.load_cert_string(cert)
    s = sig
    sig = base64.decodestring(s)

    print "Validations: \n"
    print " - Validating signature"
    pub_key = cert.get_pubkey()
    pub_key.verify_init()
    pub_key.verify_update(str(field))
    valid_sig = pub_key.verify_final(sig)
    if valid_sig != 1:
        return False

    # verify if certificate is valid
    print " - Validating certificate and certificate chain"
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_pem())
    chain = generateCertChain(certificate)
    valid_cert = verifyChain(chain, certificate)
    if valid_cert != None:
        return False

    # validate signature time
    sigtime_isValid = validateSigTime(certificate, dt)

    if not sigtime_isValid:
        print "Invalid signature time"
        return False

    return True
