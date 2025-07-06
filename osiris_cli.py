#!/usr/bin/env python3
"""
Interface en ligne de commande pour Osiris
Collecteur forensique multi-OS
"""

import argparse
import json
import sys
import logging
from datetime import datetime
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_argparse():
    """Configure l'analyseur d'arguments"""
    parser = argparse.ArgumentParser(
        description='Osiris - Collecteur forensique multi-OS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python osiris_cli.py --list                    # Liste tous les collecteurs
  python osiris_cli.py --collect-all             # Collecte tous les artefacts
  python osiris_cli.py --collect processes       # Collecte les processus
  python osiris_cli.py --collect services --output results.json
  python osiris_cli.py --platform windows --collect users
        """
    )
    
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='Liste tous les collecteurs disponibles'
    )
    
    parser.add_argument(
        '--collect-all', '-a',
        action='store_true',
        help='Collecte tous les artefacts disponibles'
    )
    
    parser.add_argument(
        '--collect', '-c',
        metavar='COLLECTOR',
        help='Collecte un artefact spécifique'
    )
    
    parser.add_argument(
        '--platform', '-p',
        choices=['windows', 'linux', 'macos'],
        help='Plateforme spécifique (par défaut: détection automatique)'
    )
    
    parser.add_argument(
        '--output', '-o',
        metavar='FILE',
        help='Fichier de sortie JSON (par défaut: stdout)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mode verbeux'
    )
    
    parser.add_argument(
        '--system-info',
        action='store_true',
        help='Affiche les informations système'
    )
    
    return parser

def main():
    """Fonction principale"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Configuration du niveau de logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Import du gestionnaire universel
        from collectors import universal_manager, collect_all, collect_specific, list_collectors, get_system_info
        
        # Affichage des informations système
        if args.system_info:
            info = get_system_info()
            print("=== Informations Système ===")
            print(f"Plateforme: {info['platform']}")
            print(f"Plateformes disponibles: {', '.join(info['available_platforms'])}")
            print(f"Nombre de collecteurs: {info['collectors_count']}")
            print(f"Timestamp: {info['timestamp']}")
            return
        
        # Liste des collecteurs
        if args.list:
            collectors = list_collectors(args.platform)
            print("=== Collecteurs Disponibles ===")
            for platform, collector_list in collectors.items():
                print(f"\n{platform.upper()}:")
                for collector in collector_list:
                    print(f"  - {collector}")
            return
        
        # Collecte de tous les artefacts
        if args.collect_all:
            print("🔍 Collecte de tous les artefacts...")
            results = collect_all(args.platform)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False, default=str)
                print(f"✅ Résultats sauvegardés dans {args.output}")
            else:
                print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
            return
        
        # Collecte d'un artefact spécifique
        if args.collect:
            print(f"🔍 Collecte de l'artefact: {args.collect}")
            results = collect_specific(args.platform or 'auto', args.collect)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False, default=str)
                print(f"✅ Résultats sauvegardés dans {args.output}")
            else:
                print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
            return
        
        # Si aucun argument n'est fourni, afficher l'aide
        if len(sys.argv) == 1:
            parser.print_help()
            return
        
    except ImportError as e:
        logger.error(f"Erreur d'import: {e}")
        print("❌ Erreur: Impossible d'importer les collecteurs Osiris")
        print("Vérifiez que vous êtes dans le bon répertoire et que toutes les dépendances sont installées.")
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"Erreur inattendue: {e}")
        print(f"❌ Erreur: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 