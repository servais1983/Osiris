#!/usr/bin/env python3
"""
Script de test pour les collecteurs Linux
"""

import sys
import os
import json
from datetime import datetime

# Ajouter le répertoire racine au PYTHONPATH
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_linux_collectors():
    """Teste tous les collecteurs Linux"""
    
    print("🧪 Test des collecteurs Linux pour Osiris")
    print("=" * 50)
    
    # Vérifier que nous sommes sur Linux
    import platform
    if platform.system() != 'Linux':
        print("❌ Ce script doit être exécuté sur un système Linux")
        return False
    
    try:
        # Importer les collecteurs
        from collectors.linux import (
            SystemLogsCollector,
            ShellHistoryCollector,
            ProcessesCollector,
            NetworkCollector,
            FilesCollector,
            ServicesCollector,
            UsersCollector,
            CronJobsCollector,
            SystemdServicesCollector
        )
        
        # Liste des collecteurs à tester
        collectors = [
            ('SystemLogsCollector', SystemLogsCollector()),
            ('ShellHistoryCollector', ShellHistoryCollector()),
            ('ProcessesCollector', ProcessesCollector()),
            ('NetworkCollector', NetworkCollector()),
            ('FilesCollector', FilesCollector()),
            ('ServicesCollector', ServicesCollector()),
            ('UsersCollector', UsersCollector()),
            ('CronJobsCollector', CronJobsCollector()),
            ('SystemdServicesCollector', SystemdServicesCollector())
        ]
        
        results = {}
        success_count = 0
        
        for name, collector in collectors:
            print(f"\n🔍 Test de {name}...")
            try:
                start_time = datetime.now()
                data = collector.collect()
                end_time = datetime.now()
                
                duration = (end_time - start_time).total_seconds()
                
                if data:
                    print(f"✅ {name} - Succès ({duration:.2f}s)")
                    print(f"   Données collectées: {len(str(data))} caractères")
                    
                    # Sauvegarder les résultats
                    results[name] = {
                        'status': 'success',
                        'duration': duration,
                        'data_size': len(str(data)),
                        'timestamp': start_time.isoformat()
                    }
                    success_count += 1
                else:
                    print(f"⚠️  {name} - Aucune donnée collectée")
                    results[name] = {
                        'status': 'no_data',
                        'duration': duration,
                        'timestamp': start_time.isoformat()
                    }
                    
            except Exception as e:
                print(f"❌ {name} - Erreur: {str(e)}")
                results[name] = {
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
        
        # Résumé
        print("\n" + "=" * 50)
        print("📊 RÉSUMÉ DES TESTS")
        print("=" * 50)
        print(f"Collecteurs testés: {len(collectors)}")
        print(f"Succès: {success_count}")
        print(f"Échecs: {len(collectors) - success_count}")
        
        # Sauvegarder les résultats
        with open('linux_collectors_test_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n📄 Résultats sauvegardés dans: linux_collectors_test_results.json")
        
        return success_count > 0
        
    except ImportError as e:
        print(f"❌ Erreur d'import: {e}")
        return False
    except Exception as e:
        print(f"❌ Erreur générale: {e}")
        return False

def test_oql_runner():
    """Teste le runner OQL avec les sources Linux"""
    
    print("\n🧪 Test du runner OQL Linux")
    print("=" * 50)
    
    try:
        from agent.oql.runner import OQLRunner
        
        runner = OQLRunner()
        
        print(f"Plateforme détectée: {runner.platform}")
        print(f"Sources disponibles: {list(runner.sources.keys())}")
        
        # Test de quelques requêtes OQL
        test_queries = [
            "SELECT * FROM system_info",
            "SELECT * FROM processes",
            "SELECT * FROM network",
            "SELECT * FROM system_logs WHERE max_lines='10'"
        ]
        
        for query in test_queries:
            print(f"\n🔍 Test de la requête: {query}")
            try:
                results = list(runner.execute_query(query))
                print(f"✅ Succès - {len(results)} résultats")
            except Exception as e:
                print(f"❌ Erreur: {str(e)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test OQL: {e}")
        return False

if __name__ == '__main__':
    print("🚀 Démarrage des tests Linux pour Osiris")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Test des collecteurs
    collectors_ok = test_linux_collectors()
    
    # Test du runner OQL
    oql_ok = test_oql_runner()
    
    # Résumé final
    print("\n" + "=" * 50)
    print("🎯 RÉSUMÉ FINAL")
    print("=" * 50)
    print(f"Collecteurs Linux: {'✅' if collectors_ok else '❌'}")
    print(f"Runner OQL: {'✅' if oql_ok else '❌'}")
    
    if collectors_ok and oql_ok:
        print("\n🎉 Tous les tests sont passés avec succès!")
        sys.exit(0)
    else:
        print("\n⚠️  Certains tests ont échoué")
        sys.exit(1) 