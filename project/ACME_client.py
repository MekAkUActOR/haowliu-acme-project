import json
import datetime
import time

import requests
from requests.adapters import HTTPAdapter
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from utils import b64encode, hash


class ACME_client():
    def __init__(self):
        self.dir_obj = {}
        self.acc_kid = None

        self.key = ECC.generate(curve="p256")
        self.sign_alg = DSS.new(self.key, "fips-186-3")
        self.client_s = requests.Session()
        self.client_s.headers.update({"User-Agent": "ACME_Project"})
        self.client_s.mount('https://', HTTPAdapter(max_retries=0))
        self.jose_s = requests.Session()
        self.jose_s.headers.update({"User-Agent": "ACME_Project", "Content-Type": "application/jose+json"})
        self.jose_s.mount('https://', HTTPAdapter(max_retries=0))
        # self.client_s.verify = 'pebble.minica.pem'
        # self.jose_s.verify = 'pebble.minica.pem'

    def get_dir(self, dirc):
        resp = self.client_s.get(dirc)
        if resp.status_code == 200:
            resp_obj = resp.json()
            self.dir_obj = resp_obj
            return self.dir_obj

    def get_nonce(self):
        if self.dir_obj["newNonce"] == None:
            return False
        resp = self.client_s.get(self.dir_obj["newNonce"])
        if resp.status_code == 200 or resp.status_code == 204:
            new_nonce = resp.headers["Replay-Nonce"]
            return new_nonce

    def create_account(self):
        payload = {"termsOfServiceAgreed": True}
        jose_payload = self.create_jose_jwk(self.dir_obj["newAccount"], payload)
        jose_request = self.jose_s.post(self.dir_obj["newAccount"], json=jose_payload)

        if jose_request.status_code == 201:
            jose_request_obj = jose_request.json()
            self.account_kid = jose_request.headers["Location"]
            return jose_request_obj

    def create_key_auth(self, token):
        key = {
            "crv"   :   "P-256",
            "kty"   :   "EC",
            "x"     :   b64encode(self.key.pointQ.x.to_bytes()),
            "y"     :   b64encode(self.key.pointQ.y.to_bytes()),
        }
        hash_value = b64encode(hash(json.dumps(key, separators=(',',':')), "utf-8").digest())
        key_auth = "{}.{}".format(token, hash_value)
        return key_auth

    def create_jose_jwk(self, url, payload):
        protected = {}
        protected["alg"] = "ES256"
        protected["jwk"] = {
            "crv"   :   "P-256",
            "kty"   :   "EC",
            "x"     :   b64encode(self.key.pointQ.x.to_bytes()),
            "y"     :   b64encode(self.key.pointQ.y.to_bytes()),
        }
        protected["nonce"] = self.get_nonce()
        protected["url"] = url

        encoded_header = b64encode(json.dumps(protected))
        encoded_payload = b64encode(json.dumps(payload))
        hash_value = hash("{}.{}".format(encoded_header, encoded_payload), "ascii")
        signature = self.sign_alg.sign(hash_value)
        jose_obj = {
            "protected" :   encoded_header,
            "payload"   :   encoded_payload,
            "signature" :   b64encode(signature),
        }
        return jose_obj

    def create_jose_kid(self, url, payload):
        protected = {
            "alg"   :   "ES256",
            "kid"   :   self.account_kid,
            "nonce" :   self.get_nonce(),
            "url"   :   url,
        }
        encoded_header = b64encode(json.dumps(protected))

        if payload == "":
            encoded_payload = ""
            hash_value = hash("{}.".format(encoded_header), "ascii")
        else:
            encoded_payload = b64encode(json.dumps(payload))
            hash_value = hash("{}.{}".format(encoded_header, encoded_payload), "ascii")
        signature = self.sign_alg.sign(hash_value)
        return {
            "protected" :   encoded_header,
            "payload"   :   encoded_payload,
            "signature" :   b64encode(signature),
        }

    def issue_cert(self, domains, begin=datetime.datetime.now(datetime.timezone.utc), duration=datetime.timedelta(days=365)):
        payload = {
            "identifiers"   :   [{"type":"dns","value":domain} for domain in domains],
            "notBefore"     :   begin.isoformat(),
            "notAfter"      :   (begin + duration).isoformat(),
        }
        jose_payload = self.create_jose_kid(self.dir_obj["newOrder"], payload)
        response = self.jose_s.post(self.dir_obj["newOrder"], json=jose_payload)
        if response.status_code == 201:
            jose_request_obj = response.json()
            return jose_request_obj, response.headers["Location"]

    def auth_cert(self, auth_url, auth_scheme, cha_server, dns_server):
        payload = ""
        jose_payload = self.create_jose_kid(auth_url, payload)
        request = self.jose_s.post(auth_url, json=jose_payload)
        if request.status_code == 200:
            jose_request_obj = request.json()
            for cha in jose_request_obj["challenges"]:
                key_auth = self.create_key_auth((cha["token"]))
                if auth_scheme == "dns01" and cha["type"] == "dns-01":
                    key_auth = b64encode(hash(key_auth, "ascii").digest())
                    dns_server.update_resolver("_acme-challenge.{}".format(jose_request_obj["identifier"]["value"]), key_auth, "TXT")
                    return cha
                elif auth_scheme == "http01" and cha["type"] == "http-01":
                    cha_server.reg_cha(cha["token"], key_auth)
                    return cha

    def vali_cert(self, vali_url):
        payload = {}
        jose_payload = self.create_jose_kid(vali_url, payload)
        response = self.jose_s.post(vali_url, json=jose_payload)
        if response.status_code == 200:
            jose_request_obj = response.json()
            return jose_request_obj

    def poll_resource_status(self, order_url, success_states, failure_states):
        while True:
            payload = ""
            jose_payload = self.create_jose_kid(order_url, payload)
            jose_request = self.jose_s.post(order_url, payload, json=jose_payload)
            jose_request_obj = jose_request.json()
            if jose_request.status_code == 200:
                if jose_request_obj["status"] in success_states:
                    print("Resource {} has {} state".format(order_url, jose_request_obj["status"]))
                    return jose_request_obj
                elif jose_request_obj["status"] in failure_states:
                    print("Resource {} has {} state, treated as failure".format(order_url, jose_request_obj["status"]))
                    return False
            time.sleep(1)

    def fin_cert(self, order_url, fin_url, der):
        jose_request_obj = self.poll_resource_status(order_url, ["ready", "processing", "valid"], ["invalid"])
        if not jose_request_obj:
            return False
        payload = {"csr": b64encode(der)}
        jose_payload = self.create_jose_kid(fin_url, payload)
        response = self.jose_s.post(fin_url, json=jose_payload)
        if response.status_code == 200:
            jose_request_obj = self.poll_resource_status(order_url, ["valid"], ["ready", "invalid", "pending"])
            if jose_request_obj:
                return jose_request_obj["certificate"]
            else:
                return False

    def dl_cert(self, cert_url):
        payload = ""
        jose_payload = self.create_jose_kid(cert_url, payload)
        response = self.jose_s.post(cert_url, json=jose_payload)
        if response.status_code == 200:
            return response.content

    def revoke_cert(self, cert):
        payload = {"certificate": b64encode(cert)}
        jose_payload = self.create_jose_kid(self.dir_obj["revokeCert"], payload)
        response = self.jose_s.post(self.dir_obj["revokeCert"], json=jose_payload)
        if response.status_code == 200:
            return response.content



