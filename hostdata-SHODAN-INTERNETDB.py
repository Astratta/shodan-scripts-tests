## Script que extrai informações de determinado IP através da InternetDB do Shodan.
## Library do Shodan para Python não cobre essa API.
## Documentação da API: https://internetdb.shodan.io/

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

hostnames = ["facebook.com", "google.com"]

KEY = os.getenv("API-KEY")

def getDomainIp(domains): ## Método retorna uma lista de IPs recebendo uma lista de domínios como argumento
    baseURL = "https://api.shodan.io"
    endpoint = "/dns/resolve?"
    finalURL = "{baseURL}{endpoint}hostnames={hostnames}&key={KEY}".format(baseURL=baseURL, 
                                                                           endpoint=endpoint, 
                                                                           hostnames=",".join([ip for ip in domains]), 
                                                                           KEY=KEY)

    try:
        results = requests.get(finalURL)
        results.raise_for_status()
        return results.json()
    except requests.exceptions.HTTPError as exception:
        raise SystemError(exception)


ips = getDomainIp(hostnames)

#print(ips)

baseURL = "https://internetdb.shodan.io/"
ip=ips[hostnames[0]]
finalURL = "{baseURL}{ip}".format(baseURL = baseURL, ip = ip)


results = requests.get(finalURL)
if results.status_code == 200:
    with open("jsonData-InternetDB.json", 'w', encoding="utf-8") as file:
        file.write(json.dumps(results.json(), sort_keys=True, ensure_ascii=False ,indent=3))
else:
    print(results.status_code)