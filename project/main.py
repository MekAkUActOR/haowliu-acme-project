import argparse
import os
from threading import Thread
from flask import Flask, request
from pathlib import Path
import cryptography

from utils import gen_csr_and_key, write_cert, https_with_cert
# from Shut_HTTP_server import server as shutserver

shut_http_server = Flask(__name__)
@shut_http_server.route('/shutdown')
def route_shutdown():
    print("Shutting down...")
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

    return "Server shutting down"

def main():
    parser = argparse.ArgumentParser(description="ACME Project")
    parser.add_argument("cha_type", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", required=True, action="append")
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    main_th = Thread(target=lambda: shut_http_server.run(host="0.0.0.0", port=5003, debug=True, threaded=True, use_reloader=False))
    main_th.start()
    https_th = Thread(target=lambda: https_with_cert(args.cha_type, args.dir, args.record, args.domain, args.revoke))
    https_th.start()
    main_th.join()
    os._exit(0)

if __name__ == "__main__":
    main()