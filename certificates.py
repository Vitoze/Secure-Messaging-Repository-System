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

def verifyChain(store, cert):
    ctx = crypto.X509StoreContext(store, cert)
    result = None
    try:
        # returns None if the certificate was validated, error otherwise
        result = ctx.verify_certificate()
    except crypto.X509StoreContextError as e:
        result = [e.certificate.get_subject(), e.message]
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
            for entryname in os.listdir(CERT_PATH):
                if os.path.isfile(os.path.join(CERT_PATH, entryname)):
                    path = os.path.join(CERT_PATH, entryname)
                    #print path
                    fi=None
                    try:
                        with open(path) as f:
                            fi = f.read()
                    except:
                        print ("Cannot load cert ", entryname)

                    f_cert=None
                    if fi.startswith('-----BEGIN CERTIFICATE-----'):
                        f_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fi)
                    else:
                        f_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, fi)

                    if issuer == f_cert.get_subject().__getattr__('CN'):
                        new_cert = f_cert
                        break

        if new_cert != None:
            store.add_cert(new_cert)
        else:
            print "Cannot load cert " + new_cert
        cert = new_cert

    return store

def find(name, path):
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.startswith(name):
                return os.path.join(root, name)