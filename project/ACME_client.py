import json
import datetime
import time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from utils import b64encode, hash

client_header = {"User-Agent": "ACME_Project ver1.0"}
jose_header = {"User-Agent": "ACME_Project ver1.0", "Content-Type": "application/jose+json"}

class ACME_client():
    def __init__(self, client_s):
        self.dir_obj = {}
        self.account_kid = None
        self.key_x = None
        self.key_y = None
        self.sign_alg = None
        self.client_s = client_s

    def get_dir(self, dirc):
        resp = self.client_s.get(dirc, headers=client_header)
        if resp.status_code == 200:
            resp_obj = resp.json()
            self.dir_obj = resp_obj
            return self.dir_obj

    def get_nonce(self):
        if self.dir_obj["newNonce"] == None:
            return False
        resp = self.client_s.get(self.dir_obj["newNonce"], headers=client_header)
        if resp.status_code == 200 or resp.status_code == 204:
            new_nonce = resp.headers["Replay-Nonce"]
            return new_nonce

    def create_account(self):
        keypair = ECC.generate(curve="p256")
        self.key_x = keypair.pointQ.x
        self.key_y = keypair.pointQ.y
        self.sign_alg = DSS.new(keypair, "fips-186-3")

        protected = {}
        protected["alg"] = "ES256"
        protected["jwk"] = {
            "crv": "P-256",
            "kty": "EC",
            "x": b64encode(self.key_x.to_bytes()),
            "y": b64encode(self.key_y.to_bytes()),
        }
        protected["nonce"] = self.get_nonce()
        protected["url"] = self.dir_obj["newAccount"]
        encoded_header = b64encode(json.dumps(protected))

        payload = {"termsOfServiceAgreed": True}
        encoded_payload = b64encode(json.dumps(payload))

        hash_value = hash("{}.{}".format(encoded_header, encoded_payload), "ascii")
        signature = b64encode(self.sign_alg.sign(hash_value))

        body = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": signature,
        }
        jose_resp = self.client_s.post(self.dir_obj["newAccount"], json=body, headers=jose_header)

        if jose_resp.status_code == 201:
            jose_resp_obj = jose_resp.json()
            self.account_kid = jose_resp.headers["Location"]
            return jose_resp_obj

    def package_payload(self, url, payload):
        protected = {
            "alg": "ES256",
            "kid": self.account_kid,
            "nonce": self.get_nonce(),
            "url": url,
        }
        encoded_protected = b64encode(json.dumps(protected))

        if payload == "":
            encoded_payload = ""
            hash_value = hash("{}.".format(encoded_protected), "ascii")
        else:
            encoded_payload = b64encode(json.dumps(payload))
            hash_value = hash("{}.{}".format(encoded_protected, encoded_payload), "ascii")
        signature = b64encode(self.sign_alg.sign(hash_value))

        return {
            "protected": encoded_protected,
            "payload": encoded_payload,
            "signature": signature,
        }

    def issue_cert(self, domains, begin=datetime.datetime.now(datetime.timezone.utc), duration=datetime.timedelta(days=365)):
        payload = {
            "identifiers": [{"type":"dns","value":domain} for domain in domains],
            "notBefore": begin.isoformat(),
            "notAfter": (begin + duration).isoformat(),
        }
        body = self.package_payload(self.dir_obj["newOrder"], payload)
        resp = self.client_s.post(self.dir_obj["newOrder"], json=body, headers=jose_header)
        if resp.status_code == 201:
            order_obj = resp.json()
            return order_obj, resp.headers["Location"]

    def iden_auth(self, auth_urls, cha_type, cha_server, dns_server):
        payload = ""
        key = {
            "crv": "P-256",
            "kty": "EC",
            "x": b64encode(self.key_x.to_bytes()),
            "y": b64encode(self.key_y.to_bytes()),
        }
        hash_value = b64encode(hash(json.dumps(key, separators=(',', ':')), "utf-8").digest())

        vali_urls = []
        for url in auth_urls:
            body = self.package_payload(url, payload)
            resp = self.client_s.post(url, json=body, headers=jose_header)
            if resp.status_code == 200:
                resp_obj = resp.json()
                if resp_obj["challenges"] != []:
                    for cha in resp_obj["challenges"]:
                        key_auth = "{}.{}".format(cha["token"], hash_value)
                        if cha_type == "dns01" and cha["type"] == "dns-01":
                            key_auth = b64encode(hash(key_auth, "ascii").digest())
                            dns_server.update_resolver("_acme-challenge.{}".format(resp_obj["identifier"]["value"]),
                                                       key_auth, "TXT")
                            vali_urls.append(cha["url"])
                        elif cha_type == "http01" and cha["type"] == "http-01":
                            cha_server.reg_cha(cha["token"], key_auth)
                            vali_urls.append(cha["url"])
                        else:
                            print("No corresponding type")
                            return False
                else:
                    print("Empty challenge")
                    return False
            else:
                print("Auth url invalid")
                return False
        return vali_urls
        #
        #
        #
        # body = self.package_payload(auth_url, payload)
        # resp = self.client_s.post(auth_url, json=body, headers=jose_header)
        # if resp.status_code == 200:
        #     resp_obj = resp.json()
        #     for cha in resp_obj["challenges"]:
        #         key_auth = "{}.{}".format(cha["token"], hash_value)
        #         if cha_type == "dns01" and cha["type"] == "dns-01":
        #             key_auth = b64encode(hash(key_auth, "ascii").digest())
        #             dns_server.update_resolver("_acme-challenge.{}".format(resp_obj["identifier"]["value"]), key_auth, "TXT")
        #             return cha
        #         elif cha_type == "http01" and cha["type"] == "http-01":
        #             cha_server.reg_cha(cha["token"], key_auth)
        #             return cha
        # else:
        #     return False

    def resp_cha(self, vali_urls):
        payload = {}
        for url in vali_urls:
            body = self.package_payload(url, payload)
            resp = self.client_s.post(url, json=body, headers=jose_header)
            if resp.status_code == 200:
                return True
            else:
                return False

        # body = self.package_payload(vali_url, payload)
        # resp = self.client_s.post(vali_url, json=body, headers=jose_header)
        # if resp.status_code == 200:
        #     resp_obj = resp.json()
        #     return resp_obj
        # else:
        #     return False

    def poll_resource_status(self, order_url, success_states, failure_states):
        while True:
            payload = ""
            body = self.package_payload(order_url, payload)
            resp = self.client_s.post(order_url, payload, json=body, headers=jose_header)
            resp_obj = resp.json()
            if resp.status_code == 200:
                if resp_obj["status"] in success_states:
                    return resp_obj
                elif resp_obj["status"] in failure_states:
                    return False
            time.sleep(1)

    def fin_order(self, order_url, fin_url, der):
        resp_obj = self.poll_resource_status(order_url, ["ready", "processing", "valid"], ["invalid"])
        if not resp_obj:
            return False
        payload = {"csr": b64encode(der)}
        body = self.package_payload(fin_url, payload)
        resp = self.client_s.post(fin_url, json=body, headers=jose_header)
        if resp.status_code == 200:
            response_obj = self.poll_resource_status(order_url, ["valid"], ["ready", "invalid", "pending"])
            if response_obj:
                return response_obj["certificate"]
            else:
                return False

    def dl_cert(self, cert_url):
        payload = ""
        body = self.package_payload(cert_url, payload)
        resp = self.client_s.post(cert_url, json=body, headers=jose_header)
        if resp.status_code == 200:
            return resp.content

    def revoke_cert(self, cert):
        payload = {"certificate": b64encode(cert)}
        body = self.package_payload(self.dir_obj["revokeCert"], payload)
        resp = self.client_s.post(self.dir_obj["revokeCert"], json=body, headers=jose_header)
        if resp.status_code == 200:
            return resp.content



