from flask import Flask


class Cert_HTTPS_server:
    def __init__(self):
        server = Flask(__name__)

        @server.route("/")
        def cert_https():
            return "HTTPS server with certificate."

        self.server = server

    def start_server(self, host, port, key, cert):
        try:
            self.server.run(host=host, port=port, ssl_context=(cert, key), threaded=True)
        except:
            print("Local Certificate does not exist.")
