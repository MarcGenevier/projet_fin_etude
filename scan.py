#!/usr/bin/env python3
import contextlib
import nmap
import requests
import socket
import subprocess

# Fonction pour scanner les ports ouverts d'un nom de domaine ou d'une adresse IP
def scan_ports(domain_or_ip):
    nm = nmap.PortScanner()

    # Résoudre le nom de domaine en adresse IP
    try:
        ip_add_entered = socket.gethostbyname(domain_or_ip)
    except socket.gaierror:
        print(f"Impossible de résoudre le nom de domaine {domain_or_ip}")
        return []

    return nm.scan(ip_add_entered, arguments="-A -O -sV")

#  --------------------------------------------------------------------------


def print_nmap_results(results):
    print("\nRésultats du scan Nmap:")
    print("PORT    STATE   SERVICE   VERSION")

    for host in results['scan']:
        host_info = results['scan'][host]
        for port, port_info in host_info['tcp'].items():
            state = port_info['state']
            service = port_info['name']
            version = port_info['version'] if 'version' in port_info else ''
            print(f"{port}/tcp {state:<7} {service:<8} {version}")

            if 'script' in port_info:
                for script_name, script_output in port_info['script'].items():
                    print(f"|_{script_name}: {script_output}")

#  --------------------------------------------------------------------------

# Fonction pour récupérer les dernières CVE à partir de l'API NVD
def get_latest_cve(num_cve=10):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage={num_cve}&orderBy=MODIFIED_DATE_DESC"
    response = requests.get(url)
    data = response.json()

    # Si la réponse de l'API ne contient pas de données, renvoyer une liste vide
    if 'result' not in data:
        return []
    
    # Extraire l'identifiant et la date de publication de chaque CVE
    cve_list = data['result']['CVE_Items']
    return [{'id': cve['cve']['CVE_data_meta']['ID'], 'date': cve['publishedDate']} for cve in cve_list]

#  --------------------------------------------------------------------------

# Fonction pour exécuter SQLMap sur une URL donnée
def run_sqlmap(target):
    try:
        # Construire la commande SQLMap avec des options pour détecter les injections SQL
        sqlmap_command = f"sqlmap -u  {target} --smart --level=5 --risk=3 --batch"
        print(f"\nExécution de SQLMap sur {target}...")
        # Lancer la commande en utilisant subprocess.Popen
        process = subprocess.Popen(sqlmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if error:
            # Si une erreur se produit, afficher le message d'erreur
            print(f"Erreur lors de l'exécution de SQLMap : {error.decode('utf-8')}")
        else:
            # Sinon, afficher la sortie de SQLMap
            print(f"Résultat de SQLMap pour {target} :")
            print(output.decode('utf-8').strip())
    except Exception as e:
        # Si une exception est levée, afficher le message d'erreur
        print(f"Erreur lors de l'exécution de SQLMap : {str(e)}")
