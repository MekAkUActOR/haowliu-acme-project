from flask import Flask
server = Flask(__name__)

from threading import Thread

@server.route("/")
def route_get():
    return "This website uses the generated certificate!"


def cert_https_server(key, cert):
    runserver = Thread(target=lambda: server.run(host="0.0.0.0", port=5001, threaded=True, debug=True, ssl_context={cert, key}, use_reloader=False))
    runserver.start()
