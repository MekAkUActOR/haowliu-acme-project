from dnslib import dns as dd
from dnslib import server as ds
from threading import Thread


class DNS_resolver:
    def __init__(self):
        self.zones = []

    def zone_add_A(self, domain, ip):
        self.zones.append(dd.RR(domain, dd.QTYPE.A, rdata=dd.A(ip), ttl=300))

    def zone_add_TXT(self, domain, txt):
        self.zones.append(dd.RR(domain, dd.QTYPE.TXT, rdata=dd.TXT(txt), ttl=300))

    def resolve(self, request):
        reply = request.reply()
        for zone in self.zones:
            reply.add_answer(zone)
        return reply


class DNS_server:
    def __init__(self):
        self.resolver = DNS_resolver()
        self.logger = ds.DNSLogger(prefix=False)
        self.server = ds.DNSServer(self.resolver, port=10053,  address="0.0.0.0", logger=self.logger)

    def zone_add_A(self, domain, ip):
        self.resolver.zone_add_A(domain, ip)

    def zone_add_TXT(self, domain, txt):
        self.resolver.zone_add_TXT(domain, txt)

    def start_server(self):
        # self.runserver = Thread(target=self.server.start)
        # self.runserver.start()
        self.server.start_thread()

    def stop_server(self):
        self.server.server.server_close()
