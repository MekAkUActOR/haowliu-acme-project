from flask import Flask, Response, abort


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

    def start_server(self, host, port):
        self.server.run(host=host, port=port, threaded=True)