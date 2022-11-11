import json
import datetime
import time

import requests
from requests.adapters import HTTPAdapter
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from utils import b64encode, hash

client_header = {"User-Agent": "ACME_Project ver1.0"}
jose_header = {"User-Agent": "ACME_Project ver1.0", "Content-Type": "application/jose+json"}

class ACME_client():
    def __init__(self):
        self.dir_obj = {}
        self.account_kid = None

        self.client_s = requests.Session()
        self.client_s.verify = 'pebble.minica.pem'
        self.client_s.mount('https://', HTTPAdapter(max_retries=0))
        self.key = ECC.generate(curve="p256")
        self.sign_alg = DSS.new(self.key, "fips-186-3")

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
        payload = {"termsOfServiceAgreed": True}

        protected = {}
        protected["alg"] = "ES256"
        protected["jwk"] = {
            "crv": "P-256",
            "kty": "EC",
            "x": b64encode(self.key.pointQ.x.to_bytes()),
            "y": b64encode(self.key.pointQ.y.to_bytes()),
        }
        protected["nonce"] = self.get_nonce()
        protected["url"] = self.dir_obj["newAccount"]

        encoded_header = b64encode(json.dumps(protected))
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

    def create_key_auth(self, token):
        key = {
            "crv": "P-256",
            "kty": "EC",
            "x": b64encode(self.key.pointQ.x.to_bytes()),
            "y": b64encode(self.key.pointQ.y.to_bytes()),
        }
        hash_value = b64encode(hash(json.dumps(key, separators=(',',':')), "utf-8").digest())
        key_auth = "{}.{}".format(token, hash_value)
        return key_auth

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

    def auth_cert(self, auth_url, auth_scheme, cha_server, dns_server):
        payload = ""
        body = self.package_payload(auth_url, payload)
        resp = self.client_s.post(auth_url, json=body, headers=jose_header)
        if resp.status_code == 200:
            resp_obj = resp.json()
            for cha in resp_obj["challenges"]:
                key_auth = self.create_key_auth((cha["token"]))
                if auth_scheme == "dns01" and cha["type"] == "dns-01":
                    key_auth = b64encode(hash(key_auth, "ascii").digest())
                    dns_server.update_resolver("_acme-challenge.{}".format(resp_obj["identifier"]["value"]), key_auth, "TXT")
                    return cha
                elif auth_scheme == "http01" and cha["type"] == "http-01":
                    cha_server.reg_cha(cha["token"], key_auth)
                    return cha

    def vali_cert(self, vali_url):
        payload = {}
        jose_payload = self.package_payload(vali_url, payload)
        response = self.client_s.post(vali_url, json=jose_payload, headers=jose_header)
        if response.status_code == 200:
            jose_request_obj = response.json()
            return jose_request_obj

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

    def fin_cert(self, order_url, fin_url, der):
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



