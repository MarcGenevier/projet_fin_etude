#!/usr/bin/env python3
import re
import subprocess

from scan import scan_ports, get_latest_cve, run_sqlmap, print_nmap_results 

# Expression régulière pour reconnaître les adresses IPv4.
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Expression régulière pour extraire le nombre de ports que vous souhaitez scanner.
# Vous devez spécifier <numéro_de_port_min>-<numéro_de_port_max> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialisation des numéros de port, les variables seront utilisées plus tard.
port_min = 0
port_max = 65535

# Ce scanner de ports utilise le module Python nmap.
# Vous devrez installer les éléments suivants pour le faire fonctionner sur Linux :
# Étape 1 : sudo apt install python3
# Étape 2 : pip install nmap
# Etape 3 : pip install requests

# En-tête d'interface utilisateur de base

# Fonction pour récupérer l'entrée de l'utilisateur (nom de domaine ou adresse IP et plage de ports à scanner)
def get_user_input():
    domain_or_ip = input("\nVeuillez entrer le nom de domaine ou l'adresse IP que vous souhaitez scanner: ")

    while True:
        # Demander à l'utilisateur la plage de ports à scanner et vérifier qu'elle est au bon format
        print("Veuillez entrer la plage de ports que vous souhaitez scanner au format: <int>-<int> (ex : 60-120)")
        port_range = input("Entrez la plage de ports: ")
        if port_range_valid := port_range_pattern.search(
            port_range.replace(" ", "")
        ):
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break

    return domain_or_ip, port_min, port_max

#  --------------------------------------------------------------------------

# Fonction pour demander à l'utilisateur s'il souhaite utiliser ProxyChains pour récupérer l'adresse IP publique
def ask_for_proxychains():
    while True:
        proxychains_choice = input("Voulez-vous utiliser ProxyChains ? (O/N) : ").lower()
        if proxychains_choice == 'o':
            return True
        elif proxychains_choice == 'n':
            return False
        else:
            print("Choix invalide. Veuillez entrer 'O' pour Oui ou 'N' pour Non.")

#  --------------------------------------------------------------------------

# Fonction pour récupérer l'adresse IP publique à l'aide de dig (commande Linux)
def get_public_ip(use_proxychains=False):
    try:
        if use_proxychains:
            # Si l'utilisateur a choisi d'utiliser ProxyChains, utiliser la commande avec ProxyChains
            command = "proxychains dig opendns.com myip.opendns.com +short"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
        else:
            # Sinon, utiliser la commande normale
            command = ['dig', '@resolver4.opendns.com', 'myip.opendns.com', '+short']
            output = subprocess.check_output(command)
            error = None

        if not error:
            return output.decode('utf-8').strip()
        print(f"Erreur lors de la récupération de l'adresse IP publique : {error.decode('utf-8')}")
        return None
    except Exception as e:
        print(f"Erreur lors de la récupération de l'adresse IP publique : {str(e)}")
        return None


#  --------------------------------------------------------------------------

# Fonction principale
def main():
    print("\n********************************************************************************************************************************")
    print("\n********************************************************************************************************************************")
    print(r"""
    |  \/  | __ _  _ _  __        / __| ___  _ _   ___ __ __(_) ___  _ _ 
    | |\/| |/ _` || '_|/ _|      | (_ |/ -_)| ' \ / -_)\ V /| |/ -_)| '_|
    |_|  |_|\__/_||_|  \__|       \___|\___||_||_|\___| \_/ |_|\___||_|  """)
    print("\n********************************************************************************************************************************")
    print("\n********************************************************************************************************************************")

    #  --------------------------------------------------------------------------

    use_proxychains = ask_for_proxychains()

    # Affichage de l'adresse IP publique
    public_ip = get_public_ip(use_proxychains)
    if public_ip is not None:
        print(f"\nVotre adresse IP publique est : {public_ip}")
    else:
        print("Impossible de récupérer l'adresse IP publique")

    #  --------------------------------------------------------------------------

    while True:
        # Affichage du menu et récupération de l'entrée de l'utilisateur
        print("\nMenu:")
        print("1. Scanner les ports")
        print("2. Afficher les dernières CVE")
        print("3. Exécuter SQLMap")
        print("4. Quitter")
        choice = input("Veuillez choisir une option (1-4): ")

        if choice == '1':
            ip_add_entered, port_min, port_max = get_user_input()
            if nmap_results := scan_ports(ip_add_entered):
                print_nmap_results(nmap_results)
            else:
                print("Aucun résultat trouvé pour le scan Nmap.")
        elif choice == '2':
            # Afficher les dernières CVE (Vulnérabilités communes exposées)
            num_cve = 20
            print(f"\nRécupération des {num_cve} dernières CVE...")
            latest_cve = get_latest_cve(num_cve)
            print("\nLes dernières CVE sont :")
            for cve_id in latest_cve:
                print(cve_id)
        elif choice == '3':
            # Exécuter SQLMap (outil d'exploitation de vulnérabilités SQL)
            target_url = input("\nVeuillez entrer l'URL ou l'adresse IP de la cible pour SQLMap: ")
            run_sqlmap(target_url)
        elif choice == '4':
            # Quitter le programme
            print("Merci d'avoir utilisé nos services !")
            break
        else:
            # Message d'erreur en cas de choix invalide
            print("Choix invalide. Veuillez choisir une option entre 1 et 4.")


#  --------------------------------------------------------------------------

# Vérifier que le code est exécuté en tant que script principal
if __name__ == "__main__":
    main()