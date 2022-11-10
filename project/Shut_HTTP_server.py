# from flask import Flask, request
#
#
# server = Flask(__name__)
#
# @server.route('/shutdown')
# def route_shutdown():
#     print("Shutting down...")
#     func = request.environ.get('werkzeug.server.shutdown')
#     if func is None:
#         raise RuntimeError('Not running with the Werkzeug Server')
#     func()
#
#     return "Server shutting down"

from flask import Flask
from utils import shutdown_server


class Shut_HTTP_server:
    def __init__(self):
        server = Flask(__name__)

        @server.route('/shutdown')
        def shutdown():
            shutdown_server()
            return "Server shutting down..."

        self.server = server

    def start_server(self, host, port):
        self.server.run(host=host, port=port, threaded=True)