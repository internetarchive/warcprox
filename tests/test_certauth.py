import os
import shutil

from warcprox.certauth import main, CertificateAuthority
import tempfile
from OpenSSL import crypto
from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.serialization import Encoding
import datetime
import time

import pytest

def setup_module():
    global TEST_CA_DIR
    TEST_CA_DIR = tempfile.mkdtemp()

    global TEST_CA_ROOT
    TEST_CA_ROOT = os.path.join(TEST_CA_DIR, 'certauth_test_ca.pem')

def teardown_module():
    shutil.rmtree(TEST_CA_DIR)
    assert not os.path.isdir(TEST_CA_DIR)
    assert not os.path.isfile(TEST_CA_ROOT)

def test_create_root():
    ret = main([TEST_CA_ROOT, '-c', 'Test Root Cert'])
    assert ret == 0

def test_create_host_cert():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', 'example.com'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)

def test_create_wildcard_host_cert_force_overwrite():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '--hostname', 'example.com', '-w', '-f'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)

def test_explicit_wildcard():
    ca = CertificateAuthority(TEST_CA_ROOT, TEST_CA_DIR, 'Test CA')
    filename = ca.get_wildcard_cert('test.example.proxy')
    certfile = os.path.join(TEST_CA_DIR, 'test.example.proxy.pem')
    assert filename == certfile
    assert os.path.isfile(certfile)
    os.remove(certfile)

def _cert_cn(pem_path):
    with open(pem_path, 'rb') as f:
        cert = cryptography_x509.load_pem_x509_certificate(f.read())
    return cert.subject.get_attributes_for_oid(cryptography_x509.NameOID.COMMON_NAME)[0].value

def _cert_sans(pem_path):
    with open(pem_path, 'rb') as f:
        cert = cryptography_x509.load_pem_x509_certificate(f.read())
    try:
        san_ext = cert.extensions.get_extension_for_class(cryptography_x509.SubjectAlternativeName)
        return san_ext.value.get_values_for_type(cryptography_x509.DNSName)
    except cryptography_x509.ExtensionNotFound:
        return []

def test_wildcard_cert_tld_aware():
    ca = CertificateAuthority(TEST_CA_ROOT, TEST_CA_DIR, 'Test CA')

    f = ca.get_wildcard_cert('auspost.com.au')
    assert f == os.path.join(TEST_CA_DIR, 'auspost.com.au.pem')
    assert _cert_cn(f) == 'auspost.com.au'
    assert '*.auspost.com.au' in _cert_sans(f)
    assert '*.com.au' not in _cert_sans(f)
    os.remove(f)

    f = ca.get_wildcard_cert('www.auspost.com.au')
    assert f == os.path.join(TEST_CA_DIR, 'auspost.com.au.pem')
    assert _cert_cn(f) == 'auspost.com.au'
    assert '*.auspost.com.au' in _cert_sans(f)
    assert '*.com.au' not in _cert_sans(f)
    os.remove(f)

    f = ca.get_wildcard_cert('foo.example.com')
    assert f == os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert _cert_cn(f) == 'example.com'
    assert '*.example.com' in _cert_sans(f)
    os.remove(f)

    f = ca.get_wildcard_cert('a.b.example.com')
    assert f == os.path.join(TEST_CA_DIR, 'b.example.com.pem')
    assert _cert_cn(f) == 'b.example.com'
    assert '*.b.example.com' in _cert_sans(f)
    assert '*.example.com' not in _cert_sans(f)
    os.remove(f)

    # Don't remove; test_create_already_exists depends on it existing.
    f = ca.get_wildcard_cert('example.com')
    assert f == os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert _cert_cn(f) == 'example.com'

    f = ca.get_wildcard_cert('foo.act.gov.au')
    assert f == os.path.join(TEST_CA_DIR, 'act.gov.au.pem')
    assert _cert_cn(f) == 'act.gov.au'
    assert '*.act.gov.au' in _cert_sans(f)
    assert '*.gov.au' not in _cert_sans(f)
    os.remove(f)

def test_create_already_exists():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', 'example.com', '-w'])
    assert ret == 1
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)
    # remove now
    os.remove(certfile)

def test_create_root_already_exists():
    ret = main([TEST_CA_ROOT])
    # not created, already exists
    assert ret == 1
    # remove now
    os.remove(TEST_CA_ROOT)

# We have what might be some time zone issues with this right now
@pytest.mark.xfail
def test_create_root_subdir():
    # create a new cert in a subdirectory
    subdir = os.path.join(TEST_CA_DIR, 'subdir')

    ca_file = os.path.join(subdir, 'certauth_test_ca.pem')

    ca = CertificateAuthority(ca_file, subdir, 'Test CA',
                              cert_not_before=-60 * 60,
                              cert_not_after=60 * 60 * 24 * 3)

    assert os.path.isdir(subdir)
    assert os.path.isfile(ca_file)

    buff = ca.get_root_PKCS12()
    assert len(buff) > 0

    expected_not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60 * 60)
    expected_not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60 * 60 * 24 * 3)

    cert = crypto.load_pkcs12(buff).get_certificate()

    actual_not_before = datetime.datetime.strptime(
            cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%S%z')
    actual_not_after = datetime.datetime.strptime(
            cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%S%z')

    time.mktime(expected_not_before.utctimetuple())
    assert abs(time.mktime(actual_not_before.utctimetuple()) - time.mktime(expected_not_before.utctimetuple())) < 10
    assert abs(time.mktime(actual_not_after.utctimetuple()) - time.mktime(expected_not_after.utctimetuple())) < 10
