import argparse
import os
from threading import Thread
from flask import Flask, request

from utils import gen_csr_and_key, write_cert, https_with_cert
from Shut_HTTP_server import server as shutserver


def main():
    parser = argparse.ArgumentParser(description="ACME Project")
    parser.add_argument("challenge", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", action="append")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    main_th = Thread(target=lambda: shutserver.run(host="0.0.0.0", port=5003, debug=False, threaded=True))
    main_th.start()
    https_th = Thread(target=lambda: https_with_cert(args.challenge, args.dir, args.record, args.domain, args.revoke))
    https_th.start()
    main_th.join()
    os._exit(0)


if __name__ == "__main__":
    main()

