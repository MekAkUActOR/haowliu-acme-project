import argparse
import os
from threading import Thread
from flask import Flask, request

from utils import gen_csr_and_key, write_cert, https_with_cert, server_thread
from Shut_HTTP_server import Shut_HTTP_server
from ACME_client import ACME_client
from DNS_server import DNS_server
from Cha_HTTP_server import Cha_HTTP_server

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
        dns_server.zone_add_A(d, args.record)
    dns_server.server_run()
    acme_client = ACME_client(args.dir, dns_server)
    if not acme_client:
        print("ACME Client failed")
        os._exit(0)

    shutserver = Shut_HTTP_server()
    shut_th = server_thread(shutserver, args=("0.0.0.0", 5003))
    https_th = Thread(target=lambda: https_with_cert(acme_client, cha_http_server, args.cha_type, args.domain, args.revoke))
    https_th.start()
    shut_th.join()
    os._exit(0)

if __name__ == "__main__":
    main()