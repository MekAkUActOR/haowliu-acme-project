# from flask import Flask
# server = Flask(__name__)
#
# from threading import Thread
#
# @server.route("/")
# def route_get():
#     return "This website uses the generated certificate!"
#
#
# def cert_https_server(key, cert):
#     runserver = Thread(target=lambda: server.run(host="0.0.0.0", port=5001, threaded=True, debug=False, ssl_context=(cert, key)))
#     runserver.start()


from flask import Flask


class Cert_HTTPS_server:
    def __init__(self):
        server = Flask(__name__)

        @server.route("/")
        def cert_https():
            return "HTTPS server with certificate."

        self.server = server

    def start_server(self, host, port, key, cert):
        self.server.run(host=host, port=port, ssl_context=(cert, key), threaded=True)
