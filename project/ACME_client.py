import base64
import json
import datetime
import time

import requests
from requests.adapters import HTTPAdapter
from requests.models import Response
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from Cha_HTTP_server import reg_httpcha


class ACME_client():
    def __init__(self, dirc, dns_server):
        self.dir = dirc
        self.dns_server = dns_server
        self.revoke_cert_url = None
        self.new_nonce_url = None
        self.new_account_url = None
        self.new_order_url = None
        self.account_kid = None
        self.key = None
        self.sign_alg = None
        self.client_session = requests.Session()
        self.jose_session = requests.Session()

        self.starting_success_states, self.starting_failure_states = ["ready", "processing", "valid"], ["invalid"]
        self.final_success_states, self.final_failure_states = ["valid"], ["ready", "invalid", "pending"]

        # self.starting_success_states = ["ready", "processing", "valid"]
        # self.starting_failure_states = ["invalid"]
        # self.final_success_states = ["valid"]
        # self.final_failure_states = ["ready", "invalid", "pending"]

        self.client_session.headers.update({"User-Agent": "ACME_Project"})
        self.client_session.mount('https://', HTTPAdapter(max_retries=0))

        self.jose_session.headers.update({"User-Agent": "ACME_Project", "Content-Type": "application/jose+json"})
        self.jose_session.mount('https://', HTTPAdapter(max_retries=0))
        self.generate_keypair()
        print("Client keypair generated")

    def generate_keypair(self):
        self.key = ECC.generate(curve="p256")
        self.sign_alg = DSS.new(self.key, "fips-180-4")

    def encode_b64(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

    def get_dir(self):
        dir_request = self.client_session.get(self.dir)
        if dir_request.status_code == 200:
            jose_request_obj = dir_request.json()
            self.revoke_cert_url = jose_request_obj["revokeCert"]
            self.new_nonce_url = jose_request_obj["newNonce"]
            self.new_account_url = jose_request_obj["newAccount"]
            self.new_order_url = jose_request_obj["newOrder"]
            return jose_request_obj

    def create_jwk_obj(self):
        return {
            "crv"   :   "P-256",
            "kid"   :   "1",
            "kty"   :   "EC",
            "x"     :   self.encode_b64(self.key.pointQ.x.to_bytes()),
            "y"     :   self.encode_b64(self.key.pointQ.y.to_bytes()),
        }

    def get_nonce(self):
        if self.new_nonce_url == None:
            return
        request = self.client_session.get(self.new_nonce_url)
        if request.status_code == 200 or request.status_code == 204:
            self.next_nonce = request.headers["Replay-Nonce"]
            return self.next_nonce

    def create_key_auth(self, token):
        key = {
            "crv"   :   "P-256",
            "kty"   :   "EC",
            "x"     :   self.encode_b64(self.key.pointQ.x.to_bytes()),
            "y"     :   self.encode_b64(self.key.pointQ.y.to_bytes()),
        }
        hash_value = self.encode_b64(SHA256.new(str.encode(json.dumps(key, separators=(',',':')), encoding="utf-8")).digest())
        key_auth = "{}.{}".format(token, hash_value)
        return key_auth

    def create_account(self):
        payload = {
            "termsOfServiceAgreed" : True,
        }
        jose_payload = self.create_jose_jwk(self.new_account_url, payload)
        jose_request = self.jose_session.post(self.new_account_url, json=jose_payload)

        if jose_request.status_code == 201:
            jose_request_obj = jose_request.json()
            self.account_kid = jose_request.headers["Location"]
            return jose_request_obj

    def create_jose_jwk(self, url, payload):
        protected = {
            "alg"   :   "ES256",
            "jwk"   :   self.create_jwk_obj(),
            "nonce" :   self.get_nonce(),
            "url"   :   url,
        }
        encoded_header = self.encode_b64(json.dumps(protected))
        encoded_payload = self.encode_b64(json.dumps(payload))
        hash_value = SHA256.new(str.encode("{}.{}".format(encoded_header, encoded_payload), encoding="ascii"))
        signature = self.sign_alg.sign(hash_value)
        jose_obj = {
            "protected" :   encoded_header,
            "payload"   :   encoded_payload,
            "signature" :   self.encode_b64(signature),
        }
        return jose_obj

    def create_jose_kid(self, url, payload):
        protected = {
            "alg"   :   "ES256",
            "kid"   :   self.account_kid,
            "nonce" :   self.get_nonce(),
            "url"   :   url,
        }
        encoded_header = self.encode_b64(json.dumps(protected))

        if payload == "":
            encoded_payload = ""
            hash_value = SHA256.new(str.encode("{}.".format(encoded_header), encoding="ascii"))
        else:
            encoded_payload = self.encode_b64(json.dumps(payload))
            hash_value = SHA256.new(str.encode("{}.{}".format(encoded_header, encoded_payload), encoding="ascii"))
        signature = self.sign_alg.sign(hash_value)
        return {
            "protected" :   encoded_header,
            "payload"   :   encoded_payload,
            "signature" :   self.encode_b64(signature),
        }

    def issue_cert(self, domains, begin=datetime.datetime.now(datetime.timezone.utc), duration=datetime.timedelta(days=365)):
        payload = {
            "identifiers"   :   [{"type":"dns","value":domain} for domain in domains],
            "notBefore"     :   begin.isoformat(),
            "notAfter"      :   (begin + duration).isoformat(),
        }
        jose_payload = self.create_jose_kid(self.new_order_url, payload)
        response = self.jose_session.post(self.new_order_url, json=jose_payload)
        if response.status_code == 201:
            jose_request_obj = response.json()
            return jose_request_obj, response.headers["Location"]

    def auth_cert(self, auth_url, auth_scheme):
        payload = ""
        jose_payload = self.create_jose_kid(auth_url, payload)
        request = self.jose_session.post(auth_url, json=jose_payload)
        if request.status_code == 200:
            jose_request_obj = request.json()
            for cha in jose_request_obj["challenges"]:
                key_auth = self.create_key_auth((cha["token"]))
                if auth_scheme == "dns01" and cha["type"] == "dns-01":
                    key_auth = self.encode_b64(SHA256.new(str.encode(key_auth, encoding="ascii")).digest())
                    self.dns_server.zone_add_TXT("_acme-challenge.{}".format(jose_request_obj["identifier"]["value"]), key_auth)
                    return cha
                elif auth_scheme == "http01" and cha["type"] == "http-01":
                    reg_httpcha(cha["token"], key_auth)
                    return cha

    def vali_cert(self, vali_url):
        payload = {}
        jose_payload = self.create_jose_kid(vali_url, payload)
        response = self.jose_session.post(vali_url, json=jose_payload)
        if response.status_code == 200:
            jose_request_obj = response.json()
            return jose_request_obj

    def poll_resource_status(self, order_url, success_states, failure_states):
        while True:
            payload = ""
            jose_payload = self.create_jose_kid(order_url, payload)
            jose_request = self.jose_session.post(order_url, payload, json=jose_payload)
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
        jose_request_obj = self.poll_resource_status(order_url, self.starting_success_states, self.starting_failure_states)
        if not jose_request_obj:
            return False
        payload = {"csr": self.encode_b64(der)}
        jose_payload = self.create_jose_kid(fin_url, payload)
        response = self.jose_session.post(fin_url, json=jose_payload)
        if response.status_code == 200:
            jose_request_obj = self.poll_resource_status(order_url, self.final_success_states, self.final_failure_states)
            if jose_request_obj:
                return jose_request_obj["certificate"]
            else:
                return False

    def dl_cert(self, cert_url):
        payload = ""
        jose_payload = self.create_jose_kid(cert_url, payload)
        response = self.jose_session.post(cert_url, json=jose_payload)
        if response.status_code == 200:
            return response.content

    def revoke_cert(self, cert):
        payload = {"certificate":self.encode_b64(cert)}
        jose_payload = self.create_jose_kid(self.revoke_cert_url, payload)
        response = self.jose_session.post(self.revoke_cert_url, json=jose_payload)
        if response.status_code == 200:
            return response.content



