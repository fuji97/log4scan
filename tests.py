import requests
from urllib import parse
# from requests import HTTPError


def test_header(endpoint, payload, timeout):
    headers = {'user-agent': payload, 'X-Api-Version': payload}
    requests.get(endpoint, headers=headers, verify=False, timeout=timeout)


def test_get(endpoint, payload, timeout):
    params = {"id": payload}
    requests.get(endpoint, params=params, verify=False, timeout=timeout)


def test_path(endpoint, payload, timeout):
    url = parse.urljoin(endpoint, parse.quote(payload, safe=''))
    requests.get(url, verify=False, timeout=timeout)


# def check_result(res):
#     try:
#         res.raise_for_status()
#     except HTTPError as e:
#         print("[ERROR] The server response is not positive", e)
