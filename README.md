# Log4Scan
### A simple automatic tool for finding vulnerable log4j hosts
![image](https://user-images.githubusercontent.com/9747718/146039311-ee3852ea-020f-434f-9aeb-3913774429e9.png)
## Installation
```shell
pip3 install -r requirements.txt
```
## Usage
```
usage: log4scan.py [-h] (-f FILENAME | -e ENDPOINT) [--http] [--https] [-p PAYLOAD] [--host HOST] [-o OUTPUT_FILE] [-m MAPPING_FILE] [-t TIMEOUT] [-v]
                   [--headers-file HEADERS] [--manual] [--proxy PROXY] [--token INTERACT_TOKEN] [--headers] [--query] [--path]

options:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        file to use as a source of endpoints (format IP:PORT)
  -e ENDPOINT, --endpoint ENDPOINT
                        endpoint to test
  --http                Test HTTP on domains without explicit schema
  --https               Test HTTPS on domains without explicit schema
  -p PAYLOAD, --payload PAYLOAD
                        template of the testing payload to use
  --host HOST           host to send LDAP request [default: interactsh.com]
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        output file with vulnerable hosts
  -m MAPPING_FILE, --mappings MAPPING_FILE
                        output file with ID<->Endpoint mapping
  -t TIMEOUT, --timeout TIMEOUT
                        request timeout [default: 10]
  -v, --verbose         verbose logging
  --headers-file HEADERS
                        file with a list of header to test
  --manual              do not run automatic verification and use the simple payload instead
  --proxy PROXY         send requests through proxy
  --token INTERACT_TOKEN
                        Custom interact.sh token

Tests:
  [default: Headers, Query, Path]

  --headers             test headers injection like user-agent and referer
  --query               test query injection in GET request as id parameter
  --path                test path injection
```
### Basic Usage
Automatically test a single endpoint
```shell
python3 log4scan.py -e https://vulnerablemachine.com
```
Automatically test multiple endpoints defined in a file
```shell
python3 log4scan.py -f ./hosts.txt
```
Manually test multiple endpoints defined in a file with private host
```shell
python3 log4scan.py -f ./hosts.txt --manual --host privatehost.net
```
Manually test multiple endpoints defined in a file with custom payload and private host
```shell
python3 log4scan.py -f ./hosts.txt --manual --payload '${jndi:ldap://HOST/customprefix-ID}' --host privatehost.net
```
Automatically test multiple endpoints defined in a file and generate two files containing the mappings between ID and endpoints and the vulnerable endpoints
```shell
python3 log4scan.py -f ./hosts.txt -m ./mapping.csv -o ./vulnerable-endpoints.txt
```

## Docker
### Execute from image
'''shell
docker run --name log4scan ghcr.io/fuji97/log4scan
'''
### Build and execute yourself
'''shell
docker build . -t log4scan
docker run --name log4scan log4scan
'''

## License
This project is licensed under **MIT License**

## Authors:
- Federico Rapetti
- Reply Communication Valley: https://www.linkedin.com/company/communication-valley
