from dnslib import dns as dd
from dnslib import server as ds
from threading import Thread


class DNS_resolver:
    def __init__(self):
        self.zone = []

    def zone_add_A(self, domain, ip):
        self.zone.append(dd.RR(domain, dd.QTYPE.A, rdata=dd.A(ip), ttl=300))

    def zone_add_TXT(self, domain, txt):
        self.zone.append(dd.RR(domain, dd.QTYPE.TXT, rdata=dd.TXT(txt), ttl=300))

    def resolve(self, request, handler):
        reply = request.reply()
        for x in self.zone:
            reply.add_answer(x)

class DNS_server:
    def __init__(self):
        self.resolver = DNS_resolver()
        self.logger = ds.DNSLogger("request,reply,truncated,error", False)
        self.server = ds.DNSServer(self.resolver, port=10053, logger=self.logger)

    def zone_add_A(self, domain, ip):
        self.resolver.zone_add_A(domain, ip)

    def zone_add_TXT(self, domain, txt):
        self.resolver.zone_add_TXT(domain, txt)

    def server_run(self):
        self.server_thread = Thread(target=self.server.start)
        self.server_thread.start()

    def server_shut(self):
        self.server.stop()