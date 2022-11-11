import argparse
import os

from utils import obtain_cert, server_thread
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
    parser.add_argument("--domain", required=True, action="append")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()

    dns_server = DNS_server()
    cha_http_server = Cha_HTTP_server()
    cha_th = server_thread(cha_http_server, args=("0.0.0.0", 5002))
    for d in args.domain:
        dns_server.update_resolver(d, args.record, "A")
    dns_server.start_server()
    acme_client = ACME_client()
    if not acme_client:
        print("ACME Client failed")
        os._exit(0)

    wrap = obtain_cert(acme_client, cha_http_server, dns_server, args)
    if not wrap:
        os._exit(0)

    shutserver = Shut_HTTP_server()
    shut_th = server_thread(shutserver, args=("0.0.0.0", 5003))
    cert_https_server = Cert_HTTPS_server()
    https_th = server_thread(cert_https_server, args=("0.0.0.0", 5001, "privatekey.pem", "certificate.pem"))
    https_th.join()
    shut_th.join()
    dns_server.stop_server()
    cha_th.join()
    os._exit(0)

if __name__ == "__main__":
    main()