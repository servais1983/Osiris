"""
Tests multi-OS pour les collecteurs Windows d'Osiris
Teste tous les collecteurs Windows avec des mocks appropriés selon l'OS
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
    if platform.system() != 'Windows':
        # Mock des modules Windows spécifiques sur Linux/macOS
        sys.modules['win32security'] = Mock()
        sys.modules['win32api'] = Mock()
        sys.modules['win32con'] = Mock()
        sys.modules['win32process'] = Mock()
        sys.modules['win32event'] = Mock()
        sys.modules['win32service'] = Mock()
        sys.modules['win32serviceutil'] = Mock()
        sys.modules['win32ts'] = Mock()
        sys.modules['win32net'] = Mock()
        sys.modules['win32netcon'] = Mock()
        sys.modules['win32profile'] = Mock()
        sys.modules['win32cred'] = Mock()
        sys.modules['win32file'] = Mock()
        sys.modules['win32timezone'] = Mock()
        sys.modules['win32evtlog'] = Mock()
        sys.modules['win32evtlogutil'] = Mock()
        sys.modules['win32gui'] = Mock()
        sys.modules['win32ui'] = Mock()
        sys.modules['win32print'] = Mock()
        sys.modules['win32com'] = Mock()
        sys.modules['pythoncom'] = Mock()
        sys.modules['winreg'] = Mock()
        sys.modules['psutil'] = Mock()
        sys.modules['yara'] = Mock()
        
        # Mock de ctypes.windll si non disponible
        if not hasattr(ctypes, 'windll'):
            ctypes.windll = Mock()
            ctypes.windll.shell32 = Mock()
            ctypes.windll.shell32.IsUserAnAdmin = Mock(return_value=0)

# Configuration des mocks avant les imports
setup_os_mocks()

# Import des modules Windows après avoir configuré les mocks
from collectors.windows import (
    WindowsCollectorManager,
    ProcessesCollector,
    WindowsServiceCollector as ServicesCollector,
    WindowsRegistryCollector as RegistryCollector,
    WindowsEventLogCollector as EventLogsCollector,
    WindowsNetworkCollector as NetworkCollector,
    WindowsFileCollector as FilesCollector,
    WindowsUserCollector as UsersCollector,
    BrowserHistoryCollector
)

def skip_if_not_windows():
    """Décorateur pour skipper les tests sur les OS non-Windows"""
    def decorator(test_method):
        def wrapper(self, *args, **kwargs):
            if platform.system() != 'Windows':
                self.skipTest(f"Test spécifique à Windows, OS actuel: {platform.system()}")
            return test_method(self, *args, **kwargs)
        return wrapper
    return decorator

class TestWindowsCollectorManagerMultiOS(unittest.TestCase):
    """Tests pour le gestionnaire de collecteurs Windows (multi-OS)"""
    
    def setUp(self):
        self.manager = WindowsCollectorManager()
    
    def test_list_collectors(self):
        """Test de la liste des collecteurs disponibles"""
        collectors = self.manager.list_collectors()
        expected = [
            'processes', 'services', 'registry', 'event_logs', 'network',
            'files', 'users', 'browser_history'
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
            'processes', 'services', 'registry', 'event_logs', 'network',
            'files', 'users', 'browser_history'
        ]
        
        for collector_name in expected_collectors:
            self.assertIn(collector_name, results)
            self.assertIsInstance(results[collector_name], dict)

class TestProcessesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de processus Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = ProcessesCollector()
    
    def test_collect_processes_multi_os(self):
        """Test de collecte des processus (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('processes', result)
        self.assertIn('suspicious_processes', result)
        self.assertIn('network_processes', result)
        self.assertIn('process_tree', result)
        self.assertIn('summary', result)
    
    def test_psutil_availability_check(self):
        """Test de la vérification de disponibilité de psutil"""
        # Vérifier que la méthode existe
        self.assertTrue(hasattr(self.collector, '_check_psutil_availability'))
        
        # Vérifier que l'attribut est défini
        self.assertTrue(hasattr(self.collector, 'psutil_available'))

class TestServicesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de services Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = ServicesCollector()
    
    def test_collect_services_multi_os(self):
        """Test de collecte des services (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('services', result)
        self.assertIn('running_services', result)
        self.assertIn('stopped_services', result)
        self.assertIn('summary', result)

class TestRegistryCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de registre Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = RegistryCollector()
    
    def test_collect_registry_multi_os(self):
        """Test de collecte du registre (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('registry_keys', result)
        self.assertIn('suspicious_keys', result)
        self.assertIn('summary', result)

class TestEventLogsCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de logs d'événements Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = EventLogsCollector()
    
    def test_collect_event_logs_multi_os(self):
        """Test de collecte des logs d'événements (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('event_logs', result)
        self.assertIn('security_events', result)
        self.assertIn('application_events', result)
        self.assertIn('summary', result)

class TestNetworkCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur réseau Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = NetworkCollector()
    
    def test_collect_network_multi_os(self):
        """Test de collecte des informations réseau (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('interfaces', result)
        self.assertIn('connections', result)
        self.assertIn('routing', result)
        self.assertIn('summary', result)

class TestFilesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de fichiers Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = FilesCollector()
    
    def test_collect_files_multi_os(self):
        """Test de collecte des fichiers (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('important_files', result)
        self.assertIn('recent_files', result)
        self.assertIn('suspicious_files', result)
        self.assertIn('summary', result)

class TestUsersCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur d'utilisateurs Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = UsersCollector()
    
    def test_collect_users_multi_os(self):
        """Test de collecte des utilisateurs (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('users', result)
        self.assertIn('groups', result)
        self.assertIn('suspicious_users', result)
        self.assertIn('summary', result)

class TestBrowserHistoryCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur d'historique de navigateur Windows (multi-OS)"""
    
    def setUp(self):
        self.collector = BrowserHistoryCollector()
    
    def test_collect_browser_history_multi_os(self):
        """Test de collecte de l'historique de navigateur (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('browser_history', result)
        self.assertIn('downloads', result)
        self.assertIn('cookies', result)
        self.assertIn('summary', result)



class TestWindowsCollectorIntegrationMultiOS(unittest.TestCase):
    """Tests d'intégration pour les collecteurs Windows (multi-OS)"""
    
    def setUp(self):
        self.manager = WindowsCollectorManager()
    
    def test_multiple_collectors_multi_os(self):
        """Test de plusieurs collecteurs ensemble (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'processes', 'services', 'registry', 'event_logs', 'network',
            'files', 'users', 'browser_history'
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

class TestWindowsCollectorErrorHandlingMultiOS(unittest.TestCase):
    """Tests de gestion d'erreurs pour les collecteurs Windows (multi-OS)"""
    
    def setUp(self):
        self.manager = WindowsCollectorManager()
    
    def test_collector_exception_handling_multi_os(self):
        """Test de gestion des exceptions dans les collecteurs (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'processes', 'services', 'registry', 'event_logs', 'network',
            'files', 'users', 'browser_history'
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