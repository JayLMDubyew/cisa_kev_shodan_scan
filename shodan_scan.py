import environment as env
import requests
import json

shodan_key = env.KEY
org = env.ORG

# get list of CVEs
def throw_http_request_error(response, url):
    print(f"ERROR: CODE {response} received when attempting to get {url}.")
    sys.exit(1)


def get_cisa_kevs():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = {'Accept': 'application/json'}
    response = requests.get(url, headers)
    if response.status_code != 200:
        throw_http_request_error(response, url)
    return response.json()

def get_shodan_vuln(org,key,cve)

vulns = get_cisa_kevs()
x = 0
for i in vulns['vulnerabilities']:
    #print(i['cveID'])
    cve = i['cveID']

    if x==10:
        break
    x += 1
