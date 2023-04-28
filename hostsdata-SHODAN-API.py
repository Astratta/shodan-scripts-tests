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

data = {}
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

def getIpData(ip): ## Método que retorna todas as informações de um IP
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

def filterIpGenData(rawdata): ## Filtra as informações gerais sobre um IP
    genKeys = ["last_update", "ip_str", "hostnames", "ports", "vulns"]

    for k in genKeys:
        if k in rawdata.keys():
            data[k]=rawdata[k]
            '''if type(rawdata[k]) is list:
                print("{k}: {valores}\n".format(k=k, valores=", ".join([str(valor) for valor in rawdata[k]])))
            else:
                print("{}: {}\n".format(k, rawdata[k]))'''
        else:
            data[k] = None

def filterIpServiceData(rawdata): ## Filtra informações de cada serviço possivelmente vulnerável por IP
    genKeys = ["product", "version", "port", "vulns"]

    for i in range(len(rawdata["data"])):
        if "vulns" in rawdata["data"][i].keys():
            data["data"].append({})
            for k in genKeys:
                if k in rawdata["data"][i].keys():
                    data["data"][-1][k] = rawdata["data"][i][k]
                    '''if k in rawdata["data"][i].keys():
                        if type(rawdata["data"][i][k]) is dict:
                            for cve in list(rawdata["data"][i][k].keys()):
                                print(cve+": ")
                                for key, info in rawdata["data"][i][k][cve].items():
                                    if key != "references":
                                        print("{}: {}".format(key, info))
                                print()
                        else:
                            print("{}: {}\n".format(k, rawdata["data"][i][k]))
                    else:
                        print("{}: null\n".format(k))'''
                else:
                    data["data"][-1][k] = None

#ips = getDomainIp(hostnames)
rawdata = getIpData("xxxxxxxxxx") ## Pega informação completa
filterIpGenData(rawdata)              ## Filtra informações gerais
data["data"] = []
filterIpServiceData(rawdata)          ## Filtra informações sobre os serviços vulneráveis

## Exporta os dados em JSON
with open("ipData.json", 'w', encoding="utf-8") as file:
    file.write(json.dumps(data, ensure_ascii=False ,indent=3))











