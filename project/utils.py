import os
import base64
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from Crypto.Hash import SHA256
from flask import request


def b64encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    b64d = base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    return b64d


def hash(data, encoding):
    encode = str.encode(data, encoding=encoding)
    hdata = SHA256.new(encode)
    return hdata


def server_thread(server, args):
    server_th = Thread(target=server.start_server, args=args)
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


def obtain_cert(acme_client, cha_http_server, dns_server, args):
    directo = acme_client.get_dir(args.dir)
    if not directo:
        return False
    account = acme_client.create_account()
    if not account:
        return False
    cert_order, order_url = acme_client.issue_cert(args.domain)
    if not cert_order:
        return False
    vali_urls = []
    fin_url = cert_order["finalize"]

    for auth in cert_order["authorizations"]:
        cert_auth = acme_client.iden_auth(auth, args.cha_type, cha_http_server, dns_server)
        if not cert_auth:
            return False
        vali_urls.append(cert_auth["url"])
    for url in vali_urls:
        cert_valid = acme_client.resp_cha(url)
        if not cert_valid:
            return False

    key, csr, der = gen_csr_and_key(args.domain)
    cert_url = acme_client.fin_order(order_url, fin_url, der)
    if not cert_url:
        return False
    dl_cert = acme_client.dl_cert(cert_url)
    if not dl_cert:
        return False

    with open("privatekey.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("certificate.pem", "wb") as f:
        f.write(dl_cert)

    if args.revoke:
        acme_client.revoke_cert(
            x509.load_pem_x509_certificate(dl_cert).public_bytes(
                serialization.Encoding.DER)
        )
    return key, dl_cert


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


