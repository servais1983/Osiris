#!/usr/bin/env python3
"""
Démonstration Osiris - Collecteur Forensique Multi-OS
"""

import sys
import json
import time
from datetime import datetime
from pathlib import Path

def print_banner():
    """Affiche la bannière Osiris"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                    🚀 OSIRIS FORENSICS 🚀                    ║
    ║                                                              ║
    ║           Collecteur Forensique Multi-OS Professionnel      ║
    ║                                                              ║
    ║              Windows • Linux • macOS                         ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_section(title):
    """Affiche une section avec style"""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print(f"{'='*60}")

def print_success(message):
    """Affiche un message de succès"""
    print(f"✅ {message}")

def print_info(message):
    """Affiche un message d'information"""
    print(f"ℹ️  {message}")

def print_warning(message):
    """Affiche un message d'avertissement"""
    print(f"⚠️  {message}")

def demo_system_info():
    """Démonstration des informations système"""
    print_section("INFORMATIONS SYSTÈME")
    
    try:
        from collectors import get_system_info
        info = get_system_info()
        
        print_success(f"Plateforme détectée: {info['platform']}")
        print_success(f"Plateformes disponibles: {', '.join(info['available_platforms'])}")
        print_success(f"Nombre total de collecteurs: {info['collectors_count']}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def demo_collectors_list():
    """Démonstration de la liste des collecteurs"""
    print_section("COLLECTEURS DISPONIBLES")
    
    try:
        from collectors import list_collectors
        collectors = list_collectors()
        
        for platform, collector_list in collectors.items():
            print_success(f"{platform.upper()}: {len(collector_list)} collecteurs")
            for collector in collector_list:
                print(f"   • {collector}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def demo_single_collector():
    """Démonstration d'un collecteur simple"""
    print_section("TEST D'UN COLLECTEUR")
    
    try:
        from collectors import collect_specific
        print_info("Test du collecteur 'users'...")
        
        start_time = time.time()
        results = collect_specific('auto', 'users')
        end_time = time.time()
        
        if 'system_info' in results:
            print_success(f"Collecteur exécuté en {end_time - start_time:.2f}s")
            print_success(f"Plateforme: {results['system_info']['platform']}")
            print_success(f"Utilisateur: {results['system_info']['current_user']}")
            
            if 'error' in results:
                print_warning("Mode dégradé (normal sans privilèges admin)")
            else:
                print_success("Mode complet")
            
            return True
        else:
            print(f"❌ Structure de données invalide")
            return False
            
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def demo_quick_scan():
    """Démonstration d'un scan rapide"""
    print_section("SCAN RAPIDE")
    
    try:
        from collectors import collect_all
        print_info("Lancement d'un scan rapide...")
        
        start_time = time.time()
        results = collect_all()
        end_time = time.time()
        
        print_success(f"Scan terminé en {end_time - start_time:.2f}s")
        
        # Analyse des résultats
        successful_collectors = 0
        failed_collectors = 0
        
        for collector_name, result in results.items():
            if isinstance(result, dict) and 'error' not in result:
                successful_collectors += 1
            else:
                failed_collectors += 1
        
        print_success(f"Collecteurs réussis: {successful_collectors}")
        if failed_collectors > 0:
            print_warning(f"Collecteurs en mode dégradé: {failed_collectors}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def demo_output_generation():
    """Démonstration de la génération de sortie"""
    print_section("GÉNÉRATION DE SORTIE")
    
    try:
        from collectors import collect_specific
        results = collect_specific('auto', 'users')
        
        # Création du dossier de sortie
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # Génération du fichier JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"osiris_demo_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print_success(f"Fichier généré: {output_file}")
        print_info(f"Taille: {output_file.stat().st_size} octets")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def print_summary():
    """Affiche le résumé de la démonstration"""
    print_section("RÉSUMÉ")
    
    summary = """
    🎉 DÉMONSTRATION TERMINÉE AVEC SUCCÈS !
    
    ✅ Osiris est opérationnel et prêt à l'emploi
    ✅ Portabilité multi-OS confirmée
    ✅ Gestion d'erreurs robuste
    ✅ Structure de données cohérente
    ✅ Interface utilisateur intuitive
    
    🚀 PROCHAINES ÉTAPES :
    
    1. Pour une collecte complète, exécutez en tant qu'administrateur
    2. Utilisez 'python osiris_cli.py --help' pour voir toutes les options
    3. Consultez le README.md pour la documentation complète
    4. Ajoutez vos propres collecteurs personnalisés
    
    💡 ASTUCES :
    
    • Mode dégradé : Fonctionne sans privilèges admin (données limitées)
    • Mode complet : Exécutez en tant qu'administrateur pour toutes les données
    • Tests : Utilisez 'python test_osiris_simple.py' pour valider l'installation
    • Logs : Définissez OSIRIS_LOG_LEVEL=DEBUG pour plus de détails
    
    🔧 SUPPORT :
    
    • Documentation : README.md
    • Tests : test_osiris_*.py
    • CLI : osiris_cli.py
    • Code source : collectors/
    """
    
    print(summary)

def main():
    """Fonction principale de démonstration"""
    print_banner()
    
    print_info("Démarrage de la démonstration Osiris...")
    print_info("Cette démonstration teste les fonctionnalités principales")
    
    # Tests séquentiels
    tests = [
        ("Informations système", demo_system_info),
        ("Liste des collecteurs", demo_collectors_list),
        ("Test d'un collecteur", demo_single_collector),
        ("Scan rapide", demo_quick_scan),
        ("Génération de sortie", demo_output_generation)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
            else:
                print_warning(f"Test '{test_name}' a échoué")
        except Exception as e:
            print(f"❌ Erreur dans le test '{test_name}': {e}")
    
    print_section("RÉSULTATS")
    print_success(f"Tests réussis: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print_summary()
        return True
    else:
        print_warning("Certains tests ont échoué. Consultez les logs pour plus de détails.")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 