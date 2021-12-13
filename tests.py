import requests
from urllib import parse
# from requests import HTTPError

HEADERS = [
    "user-agent",
    "X-Api-Version",
    "referer",
    "x-forwarded-for",
    "host"
]


def test_header(endpoint, payload):
    headers = {header: payload for header in HEADERS}
    requests.get(endpoint, headers=headers)


def test_get(endpoint, payload):
    params = {"id": payload}
    requests.get(endpoint, params=params, verify=False)


def test_path(endpoint, payload):
    url = parse.urljoin(endpoint, parse.quote(payload, safe=''))
    requests.get(url)


# def check_result(res):
#     try:
#         res.raise_for_status()
#     except HTTPError as e:
#         print("[ERROR] The server response is not positive", e)
