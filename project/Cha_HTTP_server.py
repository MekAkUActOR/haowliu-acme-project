from flask import Flask, Response, abort
# server = Flask(__name__)
#
# from threading import Thread
#
# auths = {}
# @server.route('/.well-known/acme-challenge/<string:token>')
# def cha_http(token):
#     if token in auths:
#         resp = Response(auths[token], mimetype="application/octet-stream")
#         return resp
#     else:
#         abort(404)
#
#
# def reg_httpcha(token, auth):
#     auths[token] = auth
#
#
# def cha_http_server():
#     runserver = Thread(target=lambda: server.run(host="0.0.0.0", port=5002, debug=False, threaded=True))
#     runserver.start()

class Cha_HTTP_server:
    def __init__(self):
        self.chas = {}
        server = Flask(__name__)

        @server.route('/.well-known/acme-challenge/<string:token>')
        def cha_http(token):
            if token in self.chas:
                resp = Response(self.chas[token])
                resp.headers["Content-Type"] = "application/octet-stream"
                return resp
            else:
                abort(404, "Token not in challenge list")

        self.server = server

    def reg_cha(self, token, cha):
        self.chas[token] = cha

    def start_server(self):
        self.server.run(host="0.0.0.0", port=5002)


