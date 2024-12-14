import os
import random
from argparse import ArgumentParser
from datetime import datetime, timedelta
import threading

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# =================================================================
# Valid for 3 years from now
# Max validity is 39 months:
# https://casecurity.org/2015/02/19/ssl-certificate-validity-periods-limited-to-39-months-starting-in-april/
CERT_NOT_AFTER = 3 * 365 * 24 * 60 * 60

CERTS_DIR = './ca/certs/'

CERT_NAME = 'certauth sample CA'

DEF_HASH_FUNC = hashes.SHA256()


# =================================================================
class CertificateAuthority:
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
        return serialization.pkcs12.serialize_key_and_certificates(
            name=b"root",
            key=self.key,
            cert=self.cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption()
            )

    def _make_cert(self, certname):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, certname),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            random.randint(0, 2**64 - 1)
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(seconds=self.cert_not_after)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        ).add_extension(
            x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, encipher_only=False,
                          decipher_only=False), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False
        ).sign(self.key, DEF_HASH_FUNC, default_backend())
        return cert

    def generate_ca_root(self, ca_file, ca_name, hash_func=DEF_HASH_FUNC):
        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate cert
        self.key = key
        cert = self._make_cert(ca_name)

        # Write cert + key
        self.write_pem(ca_file, cert, key)
        return cert, key

    def generate_host_cert(self, host, root_cert, root_key, host_filename,
                           wildcard=False, hash_func=DEF_HASH_FUNC):

        host = host.encode('utf-8')

        # Generate CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, host.decode('utf-8')),
            ])
        ).sign(self.key, hash_func, default_backend())

        # Generate Cert
        cert_builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            root_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            random.randint(0, 2**64 - 1)
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(seconds=self.cert_not_after)
        )

        if wildcard:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(host.decode('utf-8')),
                    x509.DNSName('*.' + host.decode('utf-8')),
                ]),
                critical=False,
            )

        cert = cert_builder.sign(root_key, hash_func, default_backend())

        # Write cert + key
        self.write_pem(host_filename, cert, self.key)
        return cert, self.key

    def write_pem(self, filename, cert, key):
        with open(filename, 'wb+') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def read_pem(self, filename):
        with open(filename, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            f.seek(0)
            key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

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
