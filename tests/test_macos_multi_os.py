"""
Tests multi-OS pour les collecteurs macOS d'Osiris
Teste tous les collecteurs macOS avec des mocks appropriés selon l'OS
"""

import unittest
import sys
import os
import platform
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import datetime
import json

# Configuration des mocks selon l'OS
def setup_os_mocks():
    """Configure les mocks selon l'OS"""
    if platform.system() != 'Darwin':
        # Mock des modules macOS spécifiques sur Windows/Linux
        sys.modules['plistlib'] = Mock()
        sys.modules['CoreFoundation'] = Mock()
        sys.modules['Foundation'] = Mock()
        sys.modules['AppKit'] = Mock()
        sys.modules['Security'] = Mock()
        sys.modules['SystemConfiguration'] = Mock()
        sys.modules['LaunchServices'] = Mock()
        sys.modules['pwd'] = Mock()
        sys.modules['grp'] = Mock()
        sys.modules['psutil'] = Mock()

# Configuration des mocks avant les imports
setup_os_mocks()

# Import des modules macOS après avoir configuré les mocks
try:
    from collectors.macos import (
        MacOSCollectorManager,
        ProcessesCollector,
        ServicesCollector,
        FilesCollector,
        NetworkCollector,
        UsersCollector,
        SystemLogsCollector,
        LaunchAgentsCollector,
        PersistenceCollector
    )
    MACOS_AVAILABLE = True
except ImportError:
    MACOS_AVAILABLE = False
    # Mock des classes si les modules ne sont pas disponibles
    class MacOSCollectorManager:
        def __init__(self):
            pass
        def list_collectors(self):
            return []
        def get_collector(self, name):
            raise ValueError(f"Collecteur inconnu: {name}")
        def collect_all(self):
            return {}
    
    class ProcessesCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'processes': []}
    
    class ServicesCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'services': []}
    
    class FilesCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'files': []}
    
    class NetworkCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'network': []}
    
    class UsersCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'users': []}
    
    class SystemLogsCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'logs': []}
    
    class LaunchAgentsCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'launch_agents': []}
    
    class PersistenceCollector:
        def __init__(self):
            pass
        def collect(self):
            return {'system_info': {'platform': 'darwin'}, 'persistence': []}

def skip_if_not_macos():
    """Décorateur pour skipper les tests sur les OS non-macOS"""
    def decorator(test_method):
        def wrapper(self, *args, **kwargs):
            if platform.system() != 'Darwin':
                self.skipTest(f"Test spécifique à macOS, OS actuel: {platform.system()}")
            return test_method(self, *args, **kwargs)
        return wrapper
    return decorator

class TestMacOSCollectorManagerMultiOS(unittest.TestCase):
    """Tests pour le gestionnaire de collecteurs macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.manager = MacOSCollectorManager()
    
    def test_list_collectors(self):
        """Test de la liste des collecteurs disponibles"""
        collectors = self.manager.list_collectors()
        expected = [
            'processes', 'services', 'files', 'network', 'users',
            'system_logs', 'launch_agents', 'persistence'
        ]
        self.assertEqual(set(collectors), set(expected))
    
    def test_get_collector_valid(self):
        """Test de récupération d'un collecteur valide"""
        collector = self.manager.get_collector('processes')
        self.assertIsInstance(collector, ProcessesCollector)
    
    def test_get_collector_invalid(self):
        """Test de récupération d'un collecteur invalide"""
        with self.assertRaises(ValueError):
            self.manager.get_collector('invalid_collector')
    
    def test_collect_all_multi_os(self):
        """Test de collecte de tous les collecteurs (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'processes', 'services', 'files', 'network', 'users',
            'system_logs', 'launch_agents', 'persistence'
        ]
        
        for collector_name in expected_collectors:
            self.assertIn(collector_name, results)
            self.assertIsInstance(results[collector_name], dict)

class TestProcessesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de processus macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = ProcessesCollector()
    
    def test_collect_processes_multi_os(self):
        """Test de collecte des processus (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('processes', result)

class TestServicesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de services macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = ServicesCollector()
    
    def test_collect_services_multi_os(self):
        """Test de collecte des services (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('services', result)

class TestFilesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de fichiers macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = FilesCollector()
    
    def test_collect_files_multi_os(self):
        """Test de collecte des fichiers (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('files', result)

class TestNetworkCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur réseau macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = NetworkCollector()
    
    def test_collect_network_multi_os(self):
        """Test de collecte des informations réseau (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('network', result)

class TestUsersCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur d'utilisateurs macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = UsersCollector()
    
    def test_collect_users_multi_os(self):
        """Test de collecte des utilisateurs (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('users', result)

class TestSystemLogsCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de logs système macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = SystemLogsCollector()
    
    def test_collect_system_logs_multi_os(self):
        """Test de collecte des logs système (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('logs', result)

class TestLaunchAgentsCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de Launch Agents macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = LaunchAgentsCollector()
    
    def test_collect_launch_agents_multi_os(self):
        """Test de collecte des Launch Agents (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('launch_agents', result)

class TestPersistenceCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de persistance macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.collector = PersistenceCollector()
    
    def test_collect_persistence_multi_os(self):
        """Test de collecte de la persistance (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('persistence', result)

class TestMacOSCollectorIntegrationMultiOS(unittest.TestCase):
    """Tests d'intégration pour les collecteurs macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.manager = MacOSCollectorManager()
    
    def test_multiple_collectors_multi_os(self):
        """Test de plusieurs collecteurs ensemble (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'processes', 'services', 'files', 'network', 'users',
            'system_logs', 'launch_agents', 'persistence'
        ]
        
        for collector_name in expected_collectors:
            self.assertIn(collector_name, results)
            self.assertIsInstance(results[collector_name], dict)
            
            # Vérifier que chaque collecteur a au moins system_info
            collector_result = results[collector_name]
            self.assertIn('system_info', collector_result)
            
            # Vérifier les informations système
            system_info = collector_result['system_info']
            self.assertIn('platform', system_info)

class TestMacOSCollectorErrorHandlingMultiOS(unittest.TestCase):
    """Tests de gestion d'erreurs pour les collecteurs macOS (multi-OS)"""
    
    def setUp(self):
        if not MACOS_AVAILABLE:
            self.skipTest("Modules macOS non disponibles")
        self.manager = MacOSCollectorManager()
    
    def test_collector_exception_handling_multi_os(self):
        """Test de gestion des exceptions dans les collecteurs (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'processes', 'services', 'files', 'network', 'users',
            'system_logs', 'launch_agents', 'persistence'
        ]
        
        for collector_name in expected_collectors:
            self.assertIn(collector_name, results)
            collector_result = results[collector_name]
            
            # Vérifier que le résultat est un dictionnaire
            self.assertIsInstance(collector_result, dict)
            
            # Vérifier qu'il contient au moins system_info
            self.assertIn('system_info', collector_result)

if __name__ == '__main__':
    unittest.main(verbosity=2) 