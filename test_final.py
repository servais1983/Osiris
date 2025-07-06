#!/usr/bin/env python3
"""
Test final d'Osiris - Validation complète
"""

import sys
import json
import time
from datetime import datetime
from pathlib import Path

def print_header(title):
    """Affiche un en-tête de test"""
    print(f"\n{'='*60}")
    print(f"🧪 {title}")
    print(f"{'='*60}")

def print_success(message):
    """Affiche un succès"""
    print(f"✅ {message}")

def print_error(message):
    """Affiche une erreur"""
    print(f"❌ {message}")

def print_warning(message):
    """Affiche un avertissement"""
    print(f"⚠️  {message}")

def test_imports():
    """Test des imports"""
    print_header("TEST DES IMPORTS")
    
    try:
        import psutil
        print_success("psutil importé")
    except ImportError as e:
        print_error(f"psutil: {e}")
        return False
    
    try:
        import platform
        print_success("platform importé")
    except ImportError as e:
        print_error(f"platform: {e}")
        return False
    
    try:
        import subprocess
        print_success("subprocess importé")
    except ImportError as e:
        print_error(f"subprocess: {e}")
        return False
    
    # Test spécifique à Windows
    if platform.system() == "Windows":
        try:
            import wmi
            print_success("wmi importé")
        except ImportError:
            print_warning("wmi non disponible (optionnel)")
    
    return True

def test_system_info():
    """Test des informations système"""
    print_header("TEST INFORMATIONS SYSTÈME")
    
    try:
        from osiris import get_system_info
        info = get_system_info()
        
        required_keys = ['platform', 'hostname', 'current_user', 'python_version', 'timestamp']
        for key in required_keys:
            if key in info:
                print_success(f"{key}: {info[key]}")
            else:
                print_error(f"Clé manquante: {key}")
                return False
        
        return True
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_collectors_list():
    """Test de la liste des collecteurs"""
    print_header("TEST LISTE DES COLLECTEURS")
    
    try:
        from osiris import list_available_collectors
        collectors = list_available_collectors()
        
        if not collectors:
            print_error("Aucun collecteur trouvé")
            return False
        
        for platform, collector_list in collectors.items():
            print_success(f"{platform.upper()}: {len(collector_list)} collecteurs")
            for collector in collector_list:
                print(f"   • {collector}")
        
        return True
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_users_collector():
    """Test du collecteur d'utilisateurs"""
    print_header("TEST COLLECTEUR UTILISATEURS")
    
    try:
        from osiris import collect_users
        start_time = time.time()
        results = collect_users()
        end_time = time.time()
        
        print_success(f"Exécution en {end_time - start_time:.2f}s")
        
        # Vérification de la structure
        required_keys = ['system_info', 'data', 'summary']
        for key in required_keys:
            if key not in results:
                print_error(f"Clé manquante: {key}")
                return False
        
        # Vérification des données
        if 'users' in results['data']:
            user_count = len(results['data']['users'])
            print_success(f"Utilisateurs trouvés: {user_count}")
        else:
            print_error("Données utilisateurs manquantes")
            return False
        
        # Vérification du mode
        mode = results['summary'].get('mode', 'unknown')
        if mode == 'full':
            print_success("Mode complet")
        elif mode == 'degraded':
            print_warning("Mode dégradé (normal sans admin)")
        else:
            print_warning(f"Mode inconnu: {mode}")
        
        return True
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_processes_collector():
    """Test du collecteur de processus"""
    print_header("TEST COLLECTEUR PROCESSUS")
    
    try:
        from osiris import collect_processes
        start_time = time.time()
        results = collect_processes()
        end_time = time.time()
        
        print_success(f"Exécution en {end_time - start_time:.2f}s")
        
        # Vérification de la structure
        if 'data' not in results or 'processes' not in results['data']:
            print_error("Structure de données invalide")
            return False
        
        process_count = len(results['data']['processes'])
        print_success(f"Processus trouvés: {process_count}")
        
        if process_count == 0:
            print_warning("Aucun processus trouvé")
        elif process_count > 0:
            print_success("Collecte de processus réussie")
        
        return True
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_network_collector():
    """Test du collecteur réseau"""
    print_header("TEST COLLECTEUR RÉSEAU")
    
    try:
        from osiris import collect_network
        start_time = time.time()
        results = collect_network()
        end_time = time.time()
        
        print_success(f"Exécution en {end_time - start_time:.2f}s")
        
        # Vérification de la structure
        if 'data' not in results:
            print_error("Structure de données invalide")
            return False
        
        connections = results['data'].get('connections', [])
        interfaces = results['data'].get('interfaces', [])
        
        print_success(f"Connexions trouvées: {len(connections)}")
        print_success(f"Interfaces trouvées: {len(interfaces)}")
        
        return True
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_full_scan():
    """Test d'un scan complet"""
    print_header("TEST SCAN COMPLET")
    
    try:
        from osiris import collect_all
        start_time = time.time()
        results = collect_all()
        end_time = time.time()
        
        print_success(f"Scan complet en {end_time - start_time:.2f}s")
        
        # Analyse des résultats
        if 'collectors' not in results:
            print_error("Structure de résultats invalide")
            return False
        
        successful = results['summary'].get('successful_collectors', 0)
        failed = results['summary'].get('failed_collectors', 0)
        total = results['summary'].get('total_collectors', 0)
        
        print_success(f"Collecteurs réussis: {successful}/{total}")
        if failed > 0:
            print_warning(f"Collecteurs en mode dégradé: {failed}")
        
        return successful > 0
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_output_generation():
    """Test de la génération de sortie"""
    print_header("TEST GÉNÉRATION DE SORTIE")
    
    try:
        from osiris import collect_users, save_results
        
        # Collecte de données
        results = collect_users()
        
        # Sauvegarde
        output_file = "test_output.json"
        success = save_results(results, output_file)
        
        if success:
            # Vérification du fichier
            output_path = Path(output_file)
            if output_path.exists():
                file_size = output_path.stat().st_size
                print_success(f"Fichier généré: {output_file} ({file_size} octets)")
                
                # Test de lecture
                with open(output_file, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                
                if 'system_info' in loaded_data:
                    print_success("Fichier JSON valide")
                    return True
                else:
                    print_error("Structure JSON invalide")
                    return False
            else:
                print_error("Fichier non créé")
                return False
        else:
            print_error("Échec de la sauvegarde")
            return False
        
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 TEST FINAL OSIRIS")
    print("Validation complète de l'installation et des fonctionnalités")
    
    tests = [
        ("Imports", test_imports),
        ("Informations système", test_system_info),
        ("Liste des collecteurs", test_collectors_list),
        ("Collecteur utilisateurs", test_users_collector),
        ("Collecteur processus", test_processes_collector),
        ("Collecteur réseau", test_network_collector),
        ("Scan complet", test_full_scan),
        ("Génération de sortie", test_output_generation)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
            else:
                print_error(f"Test '{test_name}' a échoué")
        except Exception as e:
            print_error(f"Erreur dans le test '{test_name}': {e}")
    
    print_header("RÉSULTATS FINAUX")
    print_success(f"Tests réussis: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print("\n🎉 TOUS LES TESTS SONT PASSÉS !")
        print("✅ Osiris est prêt pour la production")
        print("\n🚀 Utilisation:")
        print("  python osiris.py --help")
        print("  python osiris.py --collect users --output scan.json")
        print("  python osiris.py --collect-all --output full_scan.json")
        return True
    else:
        print(f"\n⚠️  {total_tests - passed_tests} test(s) ont échoué")
        print("Consultez les erreurs ci-dessus pour résoudre les problèmes")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 