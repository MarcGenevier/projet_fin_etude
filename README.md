README.md
Port Scanner et analyseur de vulnérabilités

Ce projet est un scanner de ports et un analyseur de vulnérabilités en Python, qui utilise Nmap pour scanner les ports, récupère les dernières CVE (Vulnérabilités Communes Exposées) et exécute SQLMap pour détecter les injections SQL.
Fichiers

Le projet contient deux fichiers principaux :

    main.py : Fichier principal du programme contenant le menu, les fonctions pour récupérer les entrées utilisateur et les fonctions pour afficher les résultats.
    scan.py : Fichier contenant les fonctions pour scanner les ports, récupérer les dernières CVE et exécuter SQLMap.

Dépendances

Pour faire fonctionner ce scanner de ports, vous devrez installer les éléments suivants sur Linux :

    #!/bin/bash

    # Mise à jour des paquets
    sudo apt-get update
    sudo apt-get upgrade

    # Installation des dépendances avec apt-get
    sudo apt-get install -y sqlmap python3 proxychains 

    # Installation des dépendances avec pip
    pip install requests sqlmap proxychains python-nmap

Fonctions
main.py

    get_user_input() -> Tuple[str, int, int] :
        Description : Récupère l'entrée de l'utilisateur (nom de domaine ou adresse IP et plage de ports à scanner).
        Arguments : Aucun
        Return : Un tuple contenant le nom de domaine ou l'adresse IP, le port minimum et le port maximum de la plage de ports à scanner.

    ask_for_proxychains() -> bool :
        Description : Demande à l'utilisateur s'il souhaite utiliser ProxyChains pour récupérer l'adresse IP publique.
        Arguments : Aucun
        Return : Un booléen indiquant si l'utilisateur souhaite utiliser ProxyChains.

    get_public_ip(use_proxychains: bool = False) -> Optional[str] :
        Description : Récupère l'adresse IP publique à l'aide de dig (commande Linux).
        Arguments : use_proxychains (bool) - Indique si ProxyChains doit être utilisé pour récupérer l'adresse IP publique (facultatif, par défaut : False).
        Return : Une chaîne de caractères représentant l'adresse IP publique ou None en cas d'échec.

scan.py

    scan_ports(domain_or_ip: str) -> Dict[str, Any] :
        Description : Scan les ports ouverts d'un nom de domaine ou d'une adresse IP.
        Arguments : domain_or_ip (str) - Nom de domaine ou adresse IP à scanner.
        Return : Un dictionnaire contenant les résultats du scan Nmap.

    print_nmap_results(results: Dict[str, Any]) -> None :
        Description : Affiche les résultats du scan Nmap.
        Arguments : results (Dict) - Dictionnaire contenant les résultats du scan Nmap.
        Return : None

    get_latest_cve(num_cve: int = 10) -> List[Dict[str, str]] :
        Description : Récupère les dernières CVE à partir de l'API NVD.
        Arguments : num_cve (int) - Nombre de CVE à récupérer (facultatif, par défaut : 10).
        Return : Une liste de dictionnaires contenant l'ident


Remarque

Ce programme a été développé à des fins éducatives et de sensibilisation à la sécurité. Ne l'utilisez pas pour scanner des systèmes sans autorisation.
