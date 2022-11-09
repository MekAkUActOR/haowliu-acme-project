from flask import Flask, request
server = Flask(__name__)

from threading import Thread

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@server.route('/shutdown')
def shutdown():
    shutdown_server()
    return 'Server shutting down...'

def shut_http_server():
    runserver = Thread(target=lambda: server.run(host="0.0.0.0", port=5003, debug=True, threaded=True))
    runserver.start()
