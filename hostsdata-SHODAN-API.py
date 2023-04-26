## Script que extrai informações de determinado IP através da API do Shodan.
## O script utiliza endpoins gratuitos por enquanto.
## Aqui não faço uso da library shodan do python para que o script possa funcionar em qualquer plataforma.
## Documentação da API: https://developer.shodan.io/api

import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

hostnames = ["facebook.com", "google.com"]

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
        return list(results.json().values())
    except requests.exceptions.HTTPError as exception:
        raise SystemError(exception)

def getIpData(ip):
    endpoint = "/shodan/host/"
    finalURL = "{baseURL}{endpoint}{ip}?key={KEY}".format(baseURL=baseURL, endpoint=endpoint, ip=ip, KEY=KEY)

    try:
        results = requests.get(finalURL)
        results.raise_for_status()
        rawdata = results.json()
        datetimeObj = datetime.strptime(rawdata["last_update"], "%Y-%m-%dT%H:%M:%S.%f")
        rawdata["last_update"] = datetimeObj.strftime("%d/%m/%Y")
        return rawdata
    except requests.exceptions.HTTPError as exception:
        raise SystemError(exception)

ips = getDomainIp(hostnames)

rawdata = getIpData("xxxxxxxxxx")

genKeys = ["last_update", "ip_str", "hostnames", "ports", "vulns"]

for k in genKeys:
    if k in rawdata.keys():
        if type(rawdata[k]) is list:
            print("{k}: {valores}\n".format(k=k, valores=", ".join([str(valor) for valor in rawdata[k]])))
        else:
            print("{}: {}\n".format(k, rawdata[k]))














