import argparse
import os
import requests
from requests.adapters import HTTPAdapter

from utils import cert_manage, server_thread
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

    # Start DNS server
    dns_server = DNS_server()
    for d in args.domain:
        dns_server.update_resolver(d, args.record, "A")
    dns_server.start_server()

    # Start challenge http server
    cha_http_server = Cha_HTTP_server()
    cha_th = server_thread(cha_http_server, args=("0.0.0.0", 5002))

    # Start ACME client
    s = requests.Session()
    s.verify = 'pebble.minica.pem'
    s.mount('https://', HTTPAdapter(max_retries=0))
    acme_client = ACME_client(s)
    if not acme_client:
        print("ACME Client launch failed")
        os._exit(0)

    # Certificate Management
    wrap = cert_manage(acme_client, cha_http_server, dns_server, args)
    if not wrap:
        print("Certificate management failed")
        os._exit(0)

    # Start shut http server
    shutserver = Shut_HTTP_server()
    shut_th = server_thread(shutserver, args=("0.0.0.0", 5003))

    # Start https server with certificate
    cert_https_server = Cert_HTTPS_server()
    https_th = server_thread(cert_https_server, args=("0.0.0.0", 5001, "privatekey.pem", "certificate.pem"))

    # End process when "/shutdown"
    shut_th.join()
    dns_server.stop_server()
    os._exit(0)

if __name__ == "__main__":
    main()