""" For reference used https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https/page/2"""

import flask
import threading
import subprocess

https_server = flask.Flask(__name__)

PORT = 5001


@https_server.route("/")
def route_get():
    return "This website uses the generated certificate!"


# HTTPS server on port 5001 to use the certificate received
def start_https_server(key_path, cert_path):
    context = (cert_path, key_path)

    # https://stackoverflow.com/questions/35244577/is-it-possible-to-use-an-inline-function-in-a-thread-call
    server_thread = threading.Thread(target=lambda: https_server.run(
        host="0.0.0.0", port=PORT, debug=False, threaded=True, ssl_context=context))
    server_thread.start()

    '''server_thread = subprocess.run(https_server.run(
        host="0.0.0.0", port = PORT, debug = False, threaded=True, ssl_context=context))

    return server_thread'''