from flask import Flask, Response, abort
server = Flask(__name__)

from threading import Thread

auths = {}
@server.route('/.well-known/acme-challenge/<string:token>')
def cha_http(token):
    if token in auths:
        resp = Response(auths[token], mimetype="application/octet-stream")
        return resp
    else:
        abort(404)

def reg_httpcha(token, auth):
    auths[token] = auth

def cha_http_server():
    runserver = Thread(target=lambda: server.run(host="0.0.0.0", port=5002, debug=True, threaded=True, use_reloader=False))
    runserver.start()