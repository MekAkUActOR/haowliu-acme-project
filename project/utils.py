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


def hash_encode(data, encoding):
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


def cert_manage(acme_client, cha_http_server, dns_server, args):
    # Get resources
    dir_obj = acme_client.dir_get(args.dir)
    if not dir_obj:
        print("Get resources failed")
        return False

    # Account management
    account = acme_client.create_account()
    if not account:
        print("Account management failed")
        return False

    # Applying for certificate issuance
    cert_order, order_url = acme_client.issue_cert(args.domain)
    if not cert_order:
        print("Certificate issuance failed")
        return False

    # Identifier authorization
    if not acme_client.iden_auth(cert_order["authorizations"], args.cha_type, cha_http_server, dns_server):
        print("Identifier authorization failed")
        return False

    # Download certificate
    key, csr, der = gen_csr_and_key(args.domain)
    cert_url = acme_client.fin_order(order_url, cert_order["finalize"], der)
    if not cert_url:
        print("Finalize order failed")
        return False
    dl_cert = acme_client.dl_cert(key, cert_url, "privatekey.pem", "certificate.pem")
    if not dl_cert:
        print("Download certificate failed")
        return False

    # Certificate revocation
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


