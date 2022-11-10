import argparse
import os
from threading import Thread
from flask import Flask, request

from utils import gen_csr_and_key, write_cert, https_with_cert, server_thread
from Shut_HTTP_server import Shut_HTTP_server

def main():
    parser = argparse.ArgumentParser(description="ACME Project")
    parser.add_argument("cha_type", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", required=True, action="append")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    shutserver = Shut_HTTP_server()
    shut_th = server_thread(shutserver, None)
    https_th = Thread(target=lambda: https_with_cert(args.cha_type, args.dir, args.record, args.domain, args.revoke))
    https_th.start()
    shut_th.join()
    os._exit(0)

if __name__ == "__main__":
    main()