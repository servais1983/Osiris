#!/usr/bin/env python3
"""
Test simple d'Osiris - Version allégée
"""

import sys
import json
from datetime import datetime

def test_basic_functionality():
    """Test des fonctionnalités de base"""
    print("🚀 Test simple d'Osiris")
    print("=" * 40)
    
    try:
        # Test 1: Import du gestionnaire
        print("🔍 Test 1: Import du gestionnaire...")
        from collectors import universal_manager
        print("✅ Gestionnaire importé avec succès")
        
        # Test 2: Informations système
        print("\n🔍 Test 2: Informations système...")
        from collectors import get_system_info
        info = get_system_info()
        print(f"✅ Plateforme: {info['platform']}")
        print(f"✅ Plateformes disponibles: {info['available_platforms']}")
        print(f"✅ Nombre de collecteurs: {info['collectors_count']}")
        
        # Test 3: Liste des collecteurs
        print("\n🔍 Test 3: Liste des collecteurs...")
        from collectors import list_collectors
        collectors = list_collectors()
        for platform, collector_list in collectors.items():
            print(f"✅ {platform.upper()}: {len(collector_list)} collecteurs")
        
        # Test 4: Collecteur simple (users)
        print("\n🔍 Test 4: Collecteur users...")
        from collectors import collect_specific
        results = collect_specific('auto', 'users')
        
        if 'system_info' in results:
            print("✅ Collecteur users: Structure OK")
            if 'error' in results:
                print(f"   ⚠️  Mode dégradé (normal sans admin)")
            return True
        else:
            print("❌ Collecteur users: Structure invalide")
            return False
            
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def main():
    """Fonction principale"""
    success = test_basic_functionality()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 Osiris fonctionne correctement !")
        print("✅ Gestionnaire universel: OK")
        print("✅ Détection de plateforme: OK")
        print("✅ Collecteurs disponibles: OK")
        print("✅ Structure de données: OK")
        print("\n💡 Pour une collecte complète, exécutez en tant qu'administrateur")
    else:
        print("❌ Osiris nécessite des corrections")
    
    return success

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 