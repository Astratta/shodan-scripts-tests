## Script que extrai informações de várias listas de IPs através da API do Shodan.
## O script utiliza endpoins gratuitos por enquanto.
## Aqui não faço uso da library shodan do python para que o script possa funcionar em qualquer plataforma.
## Documentação da API: https://developer.shodan.io/api

import os
import json
import requests
import ipaddress
from time import sleep
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

KEY = os.getenv("API-KEY")
baseURL = "https://api.shodan.io"

ips = []
data = {"data": []}
orgs = ["XXXX, YYYYY, ZZZZZ"]

for o in orgs:
    with open("IPs-"+o+".txt", "r") as file: ## Nome do arquivo deve ser IPs-ORG.txt
        for address in file.readlines():
            address = address.replace("\n", "") ## Retira os '\n' lido do arquivo
            if "/" in address: ## Checa se é um ip ou um netblock
                addresses = [str(ip) for ip in ipaddress.IPv4Network(str(address))] ## Cria uma lista de IPs dado um netblock
                for i in addresses:
                    ips.append(i) ## Adiciona os IPs na lista geral
            else:
                ips.append(address) ## Adiciona o IP na lista geral

    data["data"].append({"org": o})
    data["data"][-1]["ips"] = buildData(ips, ipsData = {})

## Exporta os dados em JSON
with open("ipData.json", 'w', encoding="utf-8") as file:
    file.write(json.dumps(data, ensure_ascii=False ,indent=4))

def getIpData(ip): ## Método que retorna todas as informações de um IP
    endpoint = "/shodan/host/"
    finalURL = "{baseURL}{endpoint}{ip}?key={KEY}".format(baseURL=baseURL, endpoint=endpoint, ip=ip, KEY=KEY)

    results = requests.get(finalURL)
    rawdata = results.json()
    if results.status_code == "200":
        datetimeObj = datetime.strptime(rawdata["last_update"], "%Y-%m-%dT%H:%M:%S.%f")
        rawdata["last_update"] = datetimeObj.strftime("%d/%m/%Y")
    return rawdata

def filterData(rawdata):
    if "error" in rawdata.keys():
        return rawdata
    else:
        ipData = {}
        genKeys = ["last_update", "ip_str", "hostnames", "ports", "vulns"]

        for k in genKeys:
            if k in rawdata.keys():
                ipData[k]=rawdata[k]
            else:
                ipData[k] = None
        
        return filterIpServiceData(rawdata, ipData)

def filterIpServiceData(rawdata, ipData): ## Filtra informações de cada serviço possivelmente vulnerável por IP
    if ipData["vulns"] is None:
        return ipData
    else:
        ipData["data"] = []
        genKeys = ["product", "version", "port", "vulns"]

        for i in range(len(rawdata["data"])):
            if "vulns" in rawdata["data"][i].keys():
                ipData["data"].append({})
                for k in genKeys:
                    if k in rawdata["data"][i].keys():
                        ipData["data"][-1][k] = rawdata["data"][i][k]
                    else:
                        ipData["data"][-1][k] = None
        
        return ipData

def buildData(ips, ipsData): 
    if len(ips) < 1:
        return ipsData ## Retorna todos os dados depois que todos os IPs forem processados
    else:
        rawdata = getIpData(ips[-1]) ## Pega informação completa
        sleep(3) ## Espera 3 segundos para não cair no rate limit da API
        ipData = filterData(rawdata) ## Filtra informações mais relevantes
        ipsData[ips[-1]] = ipData ## Coloca as informações no dicioário
        ips.pop() ## Deleta o último item para poder ler um novo
        return buildData(ips, ipsData) ## Processa outro dado

'''def getDomainIp(domains): ## Método retorna uma lista de IPs recebendo uma lista de domínios como argumento 
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
        raise SystemError(exception)'''