from dnslib import dns as dd
from dnslib import server as ds


class DNS_resolver:
    def __init__(self):
        self.zones = []

    def resolve(self, request, handler):
        reply = request.reply()
        for zone in self.zones:
            reply.add_answer(zone)
        return reply


class DNS_server:
    def __init__(self):
        self.resolver = DNS_resolver()
        self.logger = ds.DNSLogger(prefix=False)
        self.server = ds.DNSServer(self.resolver, port=10053,  address="0.0.0.0", logger=self.logger)

    def update_resolver(self, domain, zone, tp):
        if tp == "A":
            self.resolver.zones.append(dd.RR(domain, dd.QTYPE.A, rdata=dd.A(zone), ttl=300))
        elif tp == "TXT":
            self.resolver.zones.append(dd.RR(domain, dd.QTYPE.TXT, rdata=dd.TXT(zone), ttl=300))

    def start_server(self):
        self.server.start_thread()

    def stop_server(self):
        self.server.server.server_close()
