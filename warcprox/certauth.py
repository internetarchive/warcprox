import logging
import os

from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM

import random
from argparse import ArgumentParser

import threading

# =================================================================
# Valid for 3 years from now
# Max validity is 39 months:
# https://casecurity.org/2015/02/19/ssl-certificate-validity-periods-limited-to-39-months-starting-in-april/
CERT_NOT_AFTER = 3 * 365 * 24 * 60 * 60

CERTS_DIR = './ca/certs/'

CERT_NAME = 'certauth sample CA'

DEF_HASH_FUNC = 'sha256'


# =================================================================
class CertificateAuthority(object):
    """
    Utility class for signing individual certificate
    with a root cert.

    Static generate_ca_root() method for creating the root cert

    All certs saved on filesystem. Individual certs are stored
    in specified certs_dir and reused if previously created.
    """

    def __init__(self, ca_file, certs_dir, ca_name,
                 overwrite=False,
                 cert_not_before=0,
                 cert_not_after=CERT_NOT_AFTER):

        assert(ca_file)
        self.ca_file = ca_file

        assert(certs_dir)
        self.certs_dir = certs_dir

        assert(ca_name)
        self.ca_name = ca_name

        self._file_created = False

        self.cert_not_before = cert_not_before
        self.cert_not_after = cert_not_after

        if not os.path.exists(certs_dir):
            os.makedirs(certs_dir)

        # if file doesn't exist or overwrite is true
        # create new root cert
        if (overwrite or not os.path.isfile(ca_file)):
            self.cert, self.key = self.generate_ca_root(ca_file, ca_name)
            self._file_created = True

        # read previously created root cert
        else:
            self.cert, self.key = self.read_pem(ca_file)

        self._lock = threading.Lock()

    def cert_for_host(self, host, overwrite=False, wildcard=False):
        with self._lock:
            host_filename = os.path.join(self.certs_dir, host) + '.pem'

            if not overwrite and os.path.exists(host_filename):
                self._file_created = False
                return host_filename

            self.generate_host_cert(host, self.cert, self.key, host_filename,
                                    wildcard)

            self._file_created = True
            return host_filename

    def get_wildcard_cert(self, cert_host):
        host_parts = cert_host.split('.', 1)
        if len(host_parts) == 2 and '.' in host_parts[1]:
            cert_host = host_parts[1]

        certfile = self.cert_for_host(cert_host,
                                      wildcard=True)

        return certfile

    def get_root_PKCS12(self):
        p12 = crypto.PKCS12()
        p12.set_certificate(self.cert)
        p12.set_privatekey(self.key)
        return p12.export()

    def _make_cert(self, certname):
        cert = crypto.X509()
        cert.set_serial_number(random.randint(0, 2 ** 64 - 1))
        cert.get_subject().CN = certname

        cert.set_version(2)
        cert.gmtime_adj_notBefore(self.cert_not_before)
        cert.gmtime_adj_notAfter(self.cert_not_after)
        return cert

    def generate_ca_root(self, ca_file, ca_name, hash_func=DEF_HASH_FUNC):
        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate cert
        cert = self._make_cert(ca_name)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints",
                                 True,
                                 b"CA:TRUE, pathlen:0"),

            crypto.X509Extension(b"keyUsage",
                                 True,
                                 b"keyCertSign, cRLSign"),

            crypto.X509Extension(b"subjectKeyIdentifier",
                                 False,
                                 b"hash",
                                 subject=cert),
            ])
        cert.sign(key, hash_func)

        # Write cert + key
        self.write_pem(ca_file, cert, key)
        return cert, key

    def generate_host_cert(self, host, root_cert, root_key, host_filename,
                           wildcard=False, hash_func=DEF_HASH_FUNC):

        host = host.encode('utf-8')

        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate CSR
        req = crypto.X509Req()
        req.get_subject().CN = host
        req.set_pubkey(key)
        req.sign(key, hash_func)

        # Generate Cert
        cert = self._make_cert(host)

        cert.set_issuer(root_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        if wildcard:
            DNS = b'DNS:'
            alt_hosts = [DNS + host,
                         DNS + b'*.' + host]

            alt_hosts = b', '.join(alt_hosts)

            cert.add_extensions([
                crypto.X509Extension(b'subjectAltName',
                                     False,
                                     alt_hosts)])

        cert.sign(root_key, hash_func)

        # Write cert + key
        self.write_pem(host_filename, cert, key)
        return cert, key

    def write_pem(self, filename, cert, key):
        with open(filename, 'wb+') as f:
            f.write(crypto.dump_privatekey(FILETYPE_PEM, key))

            f.write(crypto.dump_certificate(FILETYPE_PEM, cert))

    def read_pem(self, filename):
        with open(filename, 'r') as f:
            cert = crypto.load_certificate(FILETYPE_PEM, f.read())
            f.seek(0)
            key = crypto.load_privatekey(FILETYPE_PEM, f.read())

        return cert, key


# =================================================================
def main(args=None):
    parser = ArgumentParser(description='Certificate Authority Cert Maker Tools')

    parser.add_argument('root_ca_cert',
                        help='Path to existing or new root CA file')

    parser.add_argument('-c', '--certname', action='store', default=CERT_NAME,
                        help='Name for root certificate')

    parser.add_argument('-n', '--hostname',
                        help='Hostname certificate to create')

    parser.add_argument('-d', '--certs-dir', default=CERTS_DIR,
                        help='Directory for host certificates')

    parser.add_argument('-f', '--force', action='store_true',
                        help='Overwrite certificates if they already exist')

    parser.add_argument('-w', '--wildcard_cert', action='store_true',
                        help='add wildcard SAN to host: *.<host>, <host>')

    r = parser.parse_args(args=args)

    certs_dir = r.certs_dir
    wildcard = r.wildcard_cert

    root_cert = r.root_ca_cert
    hostname = r.hostname

    if not hostname:
        overwrite = r.force
    else:
        overwrite = False

    ca = CertificateAuthority(ca_file=root_cert,
                              certs_dir=r.certs_dir,
                              ca_name=r.certname,
                              overwrite=overwrite)

    # Just creating the root cert
    if not hostname:
        if ca._file_created:
            print('Created new root cert: "' + root_cert + '"')
            return 0
        else:
            print('Root cert "' + root_cert +
                  '" already exists,' + ' use -f to overwrite')
            return 1

    # Sign a certificate for a given host
    overwrite = r.force
    host_filename = ca.cert_for_host(hostname,
                                         overwrite, wildcard)

    if ca._file_created:
        print('Created new cert "' + hostname +
              '" signed by root cert ' +
              root_cert)
        return 0

    else:
        print('Cert for "' + hostname + '" already exists,' +
              ' use -f to overwrite')
        return 1


if __name__ == "__main__":  #pragma: no cover
    main()
