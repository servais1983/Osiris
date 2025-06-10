import os
import sys
import yaml
from pathlib import Path
from getpass import getpass

def setup_environment():
    """Configure l'environnement pour le Hive Osiris."""
    print("Configuration de l'environnement Osiris Hive...")
    
    # Vérifier si la variable d'environnement existe déjà
    if 'VT_API_KEY' in os.environ:
        print("La clé API VirusTotal est déjà configurée.")
        return
    
    # Demander la clé API de manière sécurisée
    vt_api_key = getpass("Entrez votre clé API VirusTotal (ne sera pas affichée) : ")
    
    # Vérifier que la clé n'est pas vide
    if not vt_api_key:
        print("Erreur : La clé API ne peut pas être vide.")
        sys.exit(1)
    
    # Configurer la variable d'environnement
    os.environ['VT_API_KEY'] = vt_api_key
    print("Clé API VirusTotal configurée avec succès.")
    
    # Créer le fichier .env pour le développement
    env_file = Path('.env')
    if not env_file.exists():
        with open(env_file, 'w') as f:
            f.write(f"VT_API_KEY={vt_api_key}\n")
        print("Fichier .env créé pour le développement.")
    
    # Ajouter .env au .gitignore
    gitignore = Path('.gitignore')
    if not gitignore.exists():
        with open(gitignore, 'w') as f:
            f.write(".env\n")
    else:
        with open(gitignore, 'r') as f:
            if '.env' not in f.read():
                with open(gitignore, 'a') as f:
                    f.write("\n.env\n")
    
    print("Configuration terminée.")

if __name__ == '__main__':
    setup_environment() 