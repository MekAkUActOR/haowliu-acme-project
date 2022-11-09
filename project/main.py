import os
import subprocess
import sys
import threading
import time
from pathlib import Path
import argparse

import flask

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acme_client import ACMEClient
from dns_server import newDNSServer
from https_server import start_https_server
from httpchallenge_server import start_http_challenge_server


# https://www.programcreek.com/python/?CodeExample=generate+csr
def generate_csr_key(domains):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sidray-acme-project"),
        x509.NameAttribute(NameOID.COMMON_NAME, "sidray-acme-project"),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)
                                     for domain in domains]),
        critical=False,
    ).sign(key, hashes.SHA256())

    der = csr.public_bytes(serialization.Encoding.DER)

    return key, csr, der


key_path = Path(__file__).parent.absolute() / "key.pem"
cert_path = Path(__file__).parent.absolute() / "cert.pem"


# write the cert and the pem file for the key
# https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export
def write_certificates(key, certificate):
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(certificate)


# Wrapper for obtaining the certificate using ACME client methods
def obtain_certificate(args):
    # Create DNS server object
    dns_server = newDNSServer()
    # Start the HTTP challenge server
    start_http_challenge_server()

    # Take care of multiple domains
    for domain in args.domain:
        dns_server.zone_add_A(domain, args.record)

    # Start the DNS server thread
    dns_server.server_start()
    print("[Get certificate] DNS server started")

    # Create the ACME client and use the methods defined in acme_client.py
    acme_client = ACMEClient(args.dir, dns_server)
    if not acme_client:
        print("Create client error. Process killed.")
        return False

    directory = acme_client.get_directory()
    if not directory:
        print("Get directory error. Process killed.")
        return False

    print("[Get directory]", directory)

    account = acme_client.create_account()
    if not account:
        print("Create account error. Process killed.")
        return False

    print("[Account created successfully]", account)

    certificate_order, order_url = acme_client.issue_certificate(args.domain)

    if not certificate_order:
        print("Certificate order error. Process killed.")
        return False

    print("[Placed order successfully]", certificate_order)

    validate_urls = []
    finalize_url = certificate_order["finalize"]

    for auth in certificate_order["authorizations"]:
        certificate_authorization = acme_client.authorize_certificate(auth, args.challenge)

        if not certificate_authorization:
            print("Certificate authentication error. Process killed")
            return False
        validate_urls.append(certificate_authorization["url"])

        print("[Authorized certificate successfully]", certificate_authorization)

    for url in validate_urls:
        certificate_valid = acme_client.validate_certificate(url)

        if not certificate_valid:
            print("Certificate validation error. Process killed")
            return False

        print("[Validated certificate sucessfully]", certificate_valid)

    key, csr, der = generate_csr_key(args.domain)

    certificate_url = acme_client.finalize_certificate(order_url, finalize_url, der)
    if not certificate_url:
        print("Certificate finalizing error. Process killed")
        return False

    print("[Finalized certificate]", certificate_url)

    downloaded_certificate = acme_client.download_certificate(certificate_url)

    if not downloaded_certificate:
        print("Certificate downloading error. Process killed.")
        return False

    print("[Certificate ready for download]", downloaded_certificate)

    # Write certifcate and key to files, loaded later for use.
    write_certificates(key, downloaded_certificate)

    # https://cryptography.io/en/latest/x509/reference/
    crypto_certificate = x509.load_pem_x509_certificate(downloaded_certificate)

    if args.revoke:
        acme_client.revoke_certificate(crypto_certificate.public_bytes(serialization.Encoding.DER))

    return key, downloaded_certificate


# Method to exit if no key found
def kill_all_processes():
    os._exit(0)


# Method to start https server to use the certificate
def start_server_to_use_certificate(args):
    # Get certificate, however I will read the certificate from the stored file
    key, cert = obtain_certificate(args)

    # This still happens locally, because pebble rejects 5% of the nonces
    if not key:
        print("No key found, not starting the https server, killing all..")
        kill_all_processes()

    # Trying to kill the DNS server for the invalid certificate test
    os.system("pkill -f dns_server.py")

    # Start HTTPS server to use the certificate
    start_https_server(key_path, cert_path)


# Shutdown server created inside the main script
httpshutdown_server = flask.Flask(__name__)


@httpshutdown_server.route('/shutdown')
def route_shutdown():
    print("Shutting down...")

    # https://stackoverflow.com/questions/15562446/how-to-stop-flask-application-without-using-ctrl-c
    func = flask.request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

    return "Server shutting down"


# Controller (still used to my SDN terminology haha) to initiate the certificate process, and start the https server at the end
def controller(args):
    controller_thread = threading.Thread(target=lambda: httpshutdown_server.run(
        host="0.0.0.0", port=5003, debug=False, threaded=True))
    controller_thread.start()

    https_server_thread = threading.Thread(target=lambda: start_server_to_use_certificate(args))
    https_server_thread.start()

    # Kill application when the controller terminates
    controller_thread.join()
    kill_all_processes()


def main():
    parser = argparse.ArgumentParser(description="sidray-acme-project parser")
    parser.add_argument("challenge", choices=["dns01", "http01"])
    parser.add_argument("--dir", help="the directory URL of the ACME server that should be used", required=True)
    parser.add_argument("--record", required=True,
                        help="the IPv4 address which must be returned by your DNS server for all A-record queries")
    parser.add_argument("--domain", action="append",
                        help="the domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net")
    parser.add_argument("--revoke", action="store_true",
                        help="Immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.")

    args = parser.parse_args()

    print("Parsed arguments: ", args)

    controller(args)


if __name__ == "__main__":
    main()