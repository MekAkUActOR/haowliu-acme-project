""" For reference used https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https/page/2"""

import flask
import threading
import subprocess

httpchallenge_server = flask.Flask(__name__)

PORT = 5002

auths = {}

"""
    Let’s Encrypt gives a token to your ACME client, and your ACME client puts a file on your web server at
    http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>.
    That file contains the token, plus a thumbprint of your account key.
"""
@httpchallenge_server.route('/.well-known/acme-challenge/<string:token>')
# Check for authentic token, else exit
def http_challenge(token):
    if token in auths:
        return flask.Response(auths[token], mimetype="application/octet-stream")
    else:
        flask.abort(404)

def register_http_challenge(token, auth):
    auths[token] = auth

# HTTP challenge server on PORT 5002
def start_http_challenge_server():
    # https://stackoverflow.com/questions/35244577/is-it-possible-to-use-an-inline-function-in-a-thread-call
    server_thread = threading.Thread(target = lambda: httpchallenge_server.run(
        host = "0.0.0.0", port = PORT , debug = False, threaded = True))
    server_thread.start()

    '''server_thread = subprocess.run(httpchallenge_server.run(
        host = "0.0.0.0", port = PORT , debug = False, threaded = True))
    return server_thread'''


