import environment as env
import requests
import json
import time

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
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        print(response)
        return "{" + "\n\"title\": \"ERROR\"," + "\n\"catalogVersion\": \"1970.01.01\"," + "\n\"dateReleased\": " \
                                                                                           "\"1970-01-01T00:00:00.000Z\"," \
                                                                                           "" + "\n\"count\": 0," \
                                                                                                "" + "\n\"vulnerabilities\": []} "


def get_shodan_vuln(org, key, cve):
    urlbase = f"https://api.shodan.io/shodan/host/search?key={key}&query="
    query = f"org:\"{org}\" vuln:\"{cve}\""
    headers = {'Accept': 'application/json'}
    print(urlbase + query)
    response = requests.get(urlbase + query, headers)
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        # print(response)
        print("ERROR")
        return "{'matches': [{\"product\":\"error\",\"org\":\"error\",\"isp\":\"error\",\"hostnames\":\"error\"," \
               "\"os\":\"error\",\"product\":\"error\"}], 'total': 0} "


def format_shodan_output(json_response, cve, file):
    if "total" in json_response and json_response["total"] > 0:
        for item in json_response["matches"]:

            addr = item.get("ip_str", "")
            org_name = item.get("org", "")
            isp = item.get("isp", "")

            names = item.get("hostnames", "")
            os = item.get("os", "")
            product = item.get("product", "")

            print(f"{cve},{org_name},{isp},{addr},{names},{os},{product}\n")
            file.write(f"\"{cve}\",\"{org_name}\",\"{isp}\",\"{addr}\",\"{names}\",\"{os}\",\"{product}\"\n")
        else:
            print(f"moving on.")


vulns = get_cisa_kevs()

with open("shodan_output.csv", 'w') as f:
    f.write("CVE, ORG, ISP, ADDRESS, HOSTNAMES, OS, PRODUCT\n")
    for i in vulns['vulnerabilities']:
        cve = i["cveID"]
        json_object = get_shodan_vuln(org, shodan_key, cve)
        # print(json_object) #turn on for debugging

        format_shodan_output(json_object, cve, f)
        time.sleep(1)
    # I made shodan big mad, so I have to rate limit :(
