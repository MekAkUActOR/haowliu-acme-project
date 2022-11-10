import os
import base64
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from flask import request

from ACME_client import ACME_client
from DNS_server import DNS_server
from Cha_HTTP_server import Cha_HTTP_server
from Cert_HTTPS_server import Cert_HTTPS_server
# from Shut_HTTP_server import shut_http_server


def b64encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    b64d = base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    return b64d


def server_thread(server):
    server_th = Thread(target=server.start_server)
    server_th.start()
    return server_th


def gen_csr_and_key(domains):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ACME_Project"),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    der = csr.public_bytes(serialization.Encoding.DER)
    return private_key, csr, der


def write_cert(key, cert):
    with open("privatekey.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("certificate.pem", "wb") as f:
        f.write(cert)


def obtain_cert(cha_type, dir, record, domain, revoke):
    dns_server = DNS_server()
    cha_http_server = Cha_HTTP_server()
    cha_th = server_thread(cha_http_server)
    for d in domain:
        dns_server.zone_add_A(d, record)
    dns_server.server_run()
    acme_client = ACME_client(dir, dns_server)
    if not acme_client:
        return False
    directo = acme_client.get_dir()
    if not directo:
        return False
    account = acme_client.create_account()
    if not account:
        return False
    cert_order, order_url = acme_client.issue_cert(domain)
    if not cert_order:
        return False
    vali_urls = []
    fin_url = cert_order["finalize"]
    for auth in cert_order["authorizations"]:
        cert_auth = acme_client.auth_cert(auth, cha_type, cha_http_server)
        if not cert_auth:
            return False
        vali_urls.append(cert_auth["url"])
    for url in vali_urls:
        cert_valid = acme_client.vali_cert(url)
        if not cert_valid:
            return False
    key, csr, der = gen_csr_and_key(domain)
    cert_url = acme_client.fin_cert(order_url, fin_url, der)
    if not cert_url:
        return False
    dl_cert = acme_client.dl_cert(cert_url)
    if not dl_cert:
        return False
    write_cert(key, dl_cert)
    if revoke:
        acme_client.revoke_cert(
            x509.load_pem_x509_certificate(dl_cert).public_bytes(
                serialization.Encoding.DER)
        )
    return key, dl_cert

def https_with_cert(cha_type, dir, record, domain, revoke):
    wrap = obtain_cert(cha_type, dir, record, domain, revoke)
    if not wrap:
        os._exit(0)
    os.system("pkill -f DNS_server.py")
    cert_https_server = Cert_HTTPS_server()
    https_th = Thread(target=lambda: cert_https_server.start_server("privatekey.pem", "certificate.pem"))
    https_th.start()


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


