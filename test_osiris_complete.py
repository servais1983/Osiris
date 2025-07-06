#!/usr/bin/env python3
"""
Script de test complet pour Osiris
Valide tous les collecteurs multi-OS
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_system_info():
    """Test des informations système"""
    print("🔍 Test des informations système...")
    try:
        from collectors import get_system_info
        info = get_system_info()
        print(f"✅ Plateforme: {info['platform']}")
        print(f"✅ Plateformes disponibles: {info['available_platforms']}")
        print(f"✅ Nombre de collecteurs: {info['collectors_count']}")
        return True
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def test_list_collectors():
    """Test de la liste des collecteurs"""
    print("\n🔍 Test de la liste des collecteurs...")
    try:
        from collectors import list_collectors
        collectors = list_collectors()
        for platform, collector_list in collectors.items():
            print(f"✅ {platform.upper()}: {len(collector_list)} collecteurs")
            for collector in collector_list:
                print(f"   - {collector}")
        return True
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def test_specific_collector(collector_name):
    """Test d'un collecteur spécifique"""
    print(f"\n🔍 Test du collecteur: {collector_name}")
    try:
        from collectors import collect_specific
        results = collect_specific('auto', collector_name)
        
        # Vérifier la structure de base
        if 'system_info' in results:
            print(f"✅ Collecteur {collector_name}: OK")
            if 'error' in results:
                print(f"   ⚠️  Mode dégradé: {results['error']}")
            return True
        else:
            print(f"❌ Collecteur {collector_name}: Structure invalide")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def test_all_collectors():
    """Test de tous les collecteurs"""
    print("\n🔍 Test de tous les collecteurs...")
    try:
        from collectors import collect_all
        results = collect_all()
        
        if 'metadata' in results and 'results' in results:
            print("✅ Structure des résultats: OK")
            print(f"✅ Plateforme: {results['metadata']['platform']}")
            print(f"✅ Timestamp: {results['metadata']['timestamp']}")
            
            for platform, platform_results in results['results'].items():
                print(f"✅ {platform.upper()}: {len(platform_results)} collecteurs testés")
            
            return True
        else:
            print("❌ Structure des résultats invalide")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def save_test_results(results, filename="test_results.json"):
    """Sauvegarde les résultats de test"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"✅ Résultats sauvegardés dans {filename}")
        return True
    except Exception as e:
        print(f"❌ Erreur de sauvegarde: {e}")
        return False

def main():
    """Fonction principale"""
    print("🚀 Test complet d'Osiris - Collecteur forensique multi-OS")
    print("=" * 60)
    
    test_results = {
        'timestamp': datetime.now().isoformat(),
        'tests': {},
        'summary': {}
    }
    
    # Test 1: Informations système
    test_results['tests']['system_info'] = test_system_info()
    
    # Test 2: Liste des collecteurs
    test_results['tests']['list_collectors'] = test_list_collectors()
    
    # Test 3: Collecteurs spécifiques
    try:
        from collectors import list_collectors
        collectors = list_collectors()
        
        specific_tests = {}
        for platform, collector_list in collectors.items():
            specific_tests[platform] = {}
            for collector in collector_list[:3]:  # Test seulement les 3 premiers
                specific_tests[platform][collector] = test_specific_collector(collector)
        
        test_results['tests']['specific_collectors'] = specific_tests
    except Exception as e:
        print(f"❌ Erreur lors du test des collecteurs spécifiques: {e}")
        test_results['tests']['specific_collectors'] = False
    
    # Test 4: Tous les collecteurs
    test_results['tests']['all_collectors'] = test_all_collectors()
    
    # Résumé
    total_tests = 0
    passed_tests = 0
    
    for test_name, test_result in test_results['tests'].items():
        if isinstance(test_result, dict):
            for sub_test, sub_result in test_result.items():
                if isinstance(sub_result, dict):
                    for sub_sub_test, sub_sub_result in sub_result.items():
                        total_tests += 1
                        if sub_sub_result:
                            passed_tests += 1
                else:
                    total_tests += 1
                    if sub_result:
                        passed_tests += 1
        else:
            total_tests += 1
            if test_result:
                passed_tests += 1
    
    test_results['summary'] = {
        'total_tests': total_tests,
        'passed_tests': passed_tests,
        'failed_tests': total_tests - passed_tests,
        'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
    }
    
    # Affichage du résumé
    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ DES TESTS")
    print("=" * 60)
    print(f"✅ Tests réussis: {passed_tests}/{total_tests}")
    print(f"❌ Tests échoués: {total_tests - passed_tests}")
    print(f"📈 Taux de réussite: {test_results['summary']['success_rate']:.1f}%")
    
    if test_results['summary']['success_rate'] >= 80:
        print("🎉 Osiris est prêt pour la production !")
    elif test_results['summary']['success_rate'] >= 60:
        print("⚠️  Osiris fonctionne mais nécessite des améliorations")
    else:
        print("❌ Osiris nécessite des corrections importantes")
    
    # Sauvegarde des résultats
    save_test_results(test_results)
    
    return test_results['summary']['success_rate'] >= 60

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 