## Script que extrai informações de determinado IP através da API do Shodan.
## O script utiliza endpoins gratuitos por enquanto.
## Aqui não faço uso da library shodan do python para que o script possa funcionar em qualquer plataforma.
## Documentação da API: https://developer.shodan.io/api

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

hostnames = ["chamados.yssy.com.br", "google.com"]

KEY = os.getenv("API-KEY")
baseURL = "https://api.shodan.io"

def getDomainIp(domains): ## Método retorna uma lista de IPs recebendo uma lista de domínios como argumento 
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

endpoint = "/shodan/host/"
finalURL = "{baseURL}{endpoint}{ip}?key={KEY}".format(baseURL=baseURL, endpoint=endpoint, ip='208.109.63.167', KEY=KEY)

try:
    results = requests.get(finalURL)
    results.raise_for_status()
    with open("jsonData-API.json", 'w', encoding="utf-8") as file:
        file.write(json.dumps(results.json(), sort_keys=True, ensure_ascii=False ,indent=3))
except requests.exceptions.HTTPError as exception:
    raise SystemError(exception)







