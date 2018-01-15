import M2Crypto
import PyKCS11
import sys

import time
from OpenSSL import crypto
from datetime import datetime
import os
import unicodedata


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
        print "Subject"
        subject = cert.get_subject().__getattr__('CN')
        print subject
        issuer = cert.get_issuer().__getattr__('CN')
        print issuer


        if issuer == subject:
            break
        else:
            new_cert = None
            if issuer == 'Baltimore CyberTrust Root':
                new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('/etc/ssl/certs/Baltimore_CyberTrust_Root.pem').read())
            else:
                i = unicodedata.normalize('NFKD', issuer).encode('ASCII', 'ignore')
                print i
                if find(i + '.cer', 'CCCerts/certs/') is not None:
                    new_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, open('CCCerts/certs/' + i + '.cer').read())
                if find(i + '.crt', 'CCCerts/certs/') is not None:
                    file = open('CCCerts/certs/' + i + '.crt').read()
                    if file.startswith('----'):
                        new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file)
                    else:
                        new_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, file)
                if find(i + '.pem', 'CCCerts/certs/') is not None:
                    new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('CCCerts/certs/' + i + '.pem').read())
            if new_cert != None:
                store.add_cert(new_cert)
            else:
                print "Cannot load cert " + i
            cert = new_cert
    return store

def find(name, path):
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.startswith(name):
                return os.path.join(root, name)