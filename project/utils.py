import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from ACME_client import ACME_client
from DNS_server import DNS_server
from Cha_HTTP_server import cha_http_server
from Cert_HTTPS_server import cert_https_server

# from Shut_HTTP_server import shut_http_server

key_path = Path(__file__).parent.absolute() / "key.pem"
cert_path = Path(__file__).parent.absolute() / "cert.pem"


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
    # csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    #     x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "CH"),
    #     x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
    #     x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Zurich"),
    #     x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "ACME_Project"),
    #     x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ACME_Project"),
    # ])).add_extension(
    #     x509.SubjectAlternativeName([x509.DNSName(domain)
    #                                  for domain in domains]),
    #     critical=False,
    # ).sign(private_key, hashes.SHA256())

    der = csr.public_bytes(serialization.Encoding.DER)
    return private_key, csr, der


def write_cert(key, cert):
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, "wb") as f:
        f.write(cert)


def obtain_cert(cha_type, dirc, record, domain, revoke):
    dns_server = DNS_server()
    cha_http_server()
    for d in domain:
        dns_server.zone_add_A(d, record)
    dns_server.server_run()
    acme_client = ACME_client(dirc, dns_server)
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
        cert_auth = acme_client.auth_cert(auth, cha_type)
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


def https_with_cert(cha_type, dirc, record, domain, revoke):
    key, cert = obtain_cert(cha_type, dirc, record, domain, revoke)
    if not key:
        os._exit(0)
    os.system("pkill -f DNS_server.py")
    cert_https_server(key_path, cert_path)
