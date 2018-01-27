import M2Crypto
import PyKCS11
import sys

import time
from OpenSSL import crypto
from datetime import datetime
import os
import unicodedata

CERT_PATH = 'CCCerts/certs/'
CRL_PATH = 'CCCerts/crls/'

revoked_serialN = []

def validateCertificate(cert):
    #generate store
    chain = generateCertChain(cert)
    #check if store is valid
    if verifyChain(chain, cert) == None:
        # check if certificate is not revoked
        (check, crl) = isRevoked(cert)
        if check:
            (is_valid, str)= validateCrl(crl)
            if not is_valid :
                return (False, "CRL is not valid")

        #check if certificates from store are not revoked
        while cert.get_subject().__getattr__('CN') != cert.get_issuer().__getattr__('CN'):
            issuer = cert.get_issuer().__getattr__('CN')
            issuer_cert = getCertificateFromName(issuer)

            (isvalid, str) = validateCertificate(issuer_cert)
            if not isvalid:
                return (False, "CRL is not valid")
            else:
                cert = issuer_cert

        if cert.get_subject().__getattr__('CN') == cert.get_issuer().__getattr__('CN'):
            (check, crl) = isRevoked(cert)
            if check:
                (is_valid, str) = validateCrl(crl)
                if not is_valid:
                    return (False, "CRL is not valid")
        return (True, "Certificate is valid")
    else:
        return (False, "Chain of trust verification failed")

def verifyChain(store, cert):
    ctx = crypto.X509StoreContext(store, cert)
    result = None
    try:
        # returns None if the certificate was validated, error otherwise
        result = ctx.verify_certificate()
    except crypto.X509StoreContextError as e:
        print(e.certificate.get_subject(), e.message)
    return result

def generateCertChain(cert):
    store = crypto.X509Store()
    while True:
        #print "Subject"
        subject = cert.get_subject().__getattr__('CN')
        #print subject
        issuer = cert.get_issuer().__getattr__('CN')
        #print issuer
        new_cert = None
        if issuer == subject:
            break
        elif issuer == 'Baltimore CyberTrust Root':
            new_cert = crypto.load_certificate(crypto.FILETYPE_PEM,open('/etc/ssl/certs/Baltimore_CyberTrust_Root.pem').read())
        else:
            new_cert = getCertificateFromName(issuer)
        if new_cert != None:
            store.add_cert(new_cert)
        else:
            print "Cannot load cert " + new_cert
        cert = new_cert

    return store

'''
def find(name, path):
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.startswith(name):
                return os.path.join(root, name)
'''

#Load all CRLs from CRL_PATH directory and returns a list with all the serial numbers from the revoked certificates

'''
def loadAllCrls():
    for entryname in os.listdir(CRL_PATH):
        if os.path.isfile(os.path.join(CRL_PATH, entryname)):
            crl = crypto.load_crl(crypto.FILETYPE_ASN1, open(os.path.join(CRL_PATH, entryname)).read())
            #if validateCrl(crl) != None:
            #print os.path.join(CRL_PATH, entryname)
            if crl.get_revoked() != None:
                revoked_certificates = crl.get_revoked()
                for r in revoked_certificates:
                    revoked_serialN.append(r)
'''
'''
def isRevoked(cert):
    serialN = cert.get_serial_number()
    for l in revoked_serialN:
        if serialN == l:
            return True
    return False
'''

def isRevoked(cert):
    serialN = cert.get_serial_number()
    for entryname in os.listdir(CRL_PATH):
        if os.path.isfile(os.path.join(CRL_PATH, entryname)):
            crl = crypto.load_crl(crypto.FILETYPE_ASN1, open(os.path.join(CRL_PATH, entryname)).read())
            #print os.path.join(CRL_PATH, entryname)
            revoked_certificates = crl.get_revoked()
            for r in revoked_certificates:
                if serialN == r:
                    return (True, entryname)
                else:
                    return (False, None)



def validateCrl(crl):
    i = crl.get_issuer().__getattr__('CN')
    crl_issuer = getCertificateFromName(i)
    chain = generateCertChain(crl_issuer)
    return verifyChain(chain, crl_issuer)


def getCertificateFromName(name):
    cert = None
    for entryname in os.listdir(CERT_PATH):
        if os.path.isfile(os.path.join(CERT_PATH, entryname)):
            path = os.path.join(CERT_PATH, entryname)
            # print path
            fi = None
            try:
                with open(path) as f:
                    fi = f.read()
            except:
                print ("Cannot load cert ", entryname)

            f_cert = None
            if fi.startswith('-----BEGIN CERTIFICATE-----'):
                f_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fi)
            else:
                f_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, fi)

            if name == f_cert.get_subject().__getattr__('CN'):
                cert = f_cert
                break
    return cert