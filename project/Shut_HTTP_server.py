from flask import Flask, request


server = Flask(__name__)

@server.route('/shutdown')
def route_shutdown():
    print("Shutting down...")
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

    return "Server shutting down"
