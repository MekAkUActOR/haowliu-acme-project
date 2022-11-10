import argparse
import os
from threading import Thread
from flask import Flask, request

from cryptography.hazmat.primitives import serialization
from cryptography import x509

from utils import gen_csr_and_key, write_cert, server_thread
from Shut_HTTP_server import Shut_HTTP_server
from ACME_client import ACME_client
from DNS_server import DNS_server
from Cha_HTTP_server import Cha_HTTP_server
from Cert_HTTPS_server import Cert_HTTPS_server


def main():
    parser = argparse.ArgumentParser(description="ACME Project")
    parser.add_argument("cha_type", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    dns_server = DNS_server()
    cha_http_server = Cha_HTTP_server()
    cha_th = server_thread(cha_http_server)
    for d in args.domain:
        dns_server.zone_add_A(d, args.record)
    dns_server.start_server()
    acme_client = ACME_client(args.dir, dns_server)
    if not acme_client:
        os._exit(0)
    directo = acme_client.get_dir()
    if not directo:
        os._exit(0)
    account = acme_client.create_account()
    if not account:
        os._exit(0)
    cert_order, order_url = acme_client.issue_cert(args.domain)
    if not cert_order:
        os._exit(0)
    vali_urls = []
    fin_url = cert_order["finalize"]
    for auth in cert_order["authorizations"]:
        cert_auth = acme_client.auth_cert(auth, args.cha_type, cha_http_server)
        if not cert_auth:
            os._exit(0)
        vali_urls.append(cert_auth["url"])
    for url in vali_urls:
        cert_valid = acme_client.vali_cert(url)
        if not cert_valid:
            os._exit(0)
    key, csr, der = gen_csr_and_key(args.domain)
    cert_url = acme_client.fin_cert(order_url, fin_url, der)
    if not cert_url:
        os._exit(0)
    dl_cert = acme_client.dl_cert(cert_url)
    if not dl_cert:
        os._exit(0)
    write_cert(key, dl_cert)
    if args.revoke:
        acme_client.revoke_cert(
            x509.load_pem_x509_certificate(dl_cert).public_bytes(
                serialization.Encoding.DER)
        )
    cert_https_server = Cert_HTTPS_server()
    shutserver = Shut_HTTP_server()
    shut_th = server_thread(shutserver)
    https_th = Thread(target=lambda : cert_https_server.start_server("privatekey.pem", "certificate.pem"))
    https_th.start()
    shut_th.join()
    os._exit(0)


if __name__ == "__main__":
    main()

