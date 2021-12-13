import requests
from urllib import parse
# from requests import HTTPError


def test_header(endpoint, payload):
    headers = {'user-agent': payload, 'X-Api-Version': payload}
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
