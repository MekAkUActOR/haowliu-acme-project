"Code referenced from dnslib documentation and source code"

import argparse
import datetime
import sys
import time
import threading
import traceback
import socket
import struct

import binascii, socket, struct, threading, time

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

try:
    from dnslib.server import DNSServer, DNSLogger
    from dnslib.dns import RR, DNSRecord, QTYPE, A, TXT

except ImportError:
    print("Missing dependency dnslib, Please install it with `pip`.")
    sys.exit(2)


class DNSResolver:

    def __init__(self):
        self.zone = []

    def zone_add_A(self, domain, ip):
        self.zone.append(RR(domain, QTYPE.A, rdata=A(ip), ttl=300))

    def zone_add_TXT(self, domain, txt):
        self.zone.append(RR(domain, QTYPE.TXT, rdata=TXT(txt), ttl=300))

    def resolve(self, request, handler):
        reply = request.reply()
        for z in self.zone:
            reply.add_answer(z)

        return reply


class newDNSServer:
    def __init__(self):
        self.resolver = DNSResolver()
        self.logger = DNSLogger("request,reply,truncated,error", False)
        self.server = DNSServer(self.resolver, port=10053,
                                logger=self.logger)

    def zone_add_A(self, domain, ip):
        self.resolver.zone_add_A(domain, ip)

    def zone_add_TXT(self, domain, txt):
        self.resolver.zone_add_TXT(domain, txt)

    def server_start(self):
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.start()

    def server_stop(self):
        self.server.stop()
