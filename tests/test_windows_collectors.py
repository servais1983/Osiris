"""
Tests pour les collecteurs Windows.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
from collectors.windows import (
    WindowsCollector,
    BrowserHistoryCollector,
    WindowsEventLogCollector,
    WindowsEventCollector,
    WindowsFileCollector,
    WindowsNetworkCollector,
    WindowsProcessCollector,
    WindowsRegistryCollector,
    WindowsServiceCollector,
    WindowsUserCollector
)

class TestWindowsCollectors(unittest.TestCase):
    """Tests pour les collecteurs Windows."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        self.mock_win32api = patch('win32api.GetSystemMetrics').start()
        self.mock_win32security = patch('win32security.GetTokenInformation').start()
        self.mock_win32file = patch('win32file.GetFileAttributes').start()
        self.mock_win32evtlog = patch('win32evtlog.OpenEventLog').start()
        self.mock_win32net = patch('win32net.NetUserEnum').start()
        self.mock_win32service = patch('win32serviceutil.EnumServices').start()
        self.mock_psutil = patch('psutil.process_iter').start()
        self.mock_winreg = patch('winreg.OpenKey').start()
    
    def tearDown(self):
        """Nettoyage après les tests."""
        patch.stopall()
    
    def test_base_collector(self):
        """Test du collecteur de base."""
        collector = WindowsCollector()
        self.assertIsInstance(collector, WindowsCollector)
        self.assertTrue(hasattr(collector, 'collect'))
    
    def test_browser_history_collector(self):
        """Test du collecteur d'historique de navigation."""
        collector = BrowserHistoryCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_event_logs_collector(self):
        """Test du collecteur de journaux d'événements."""
        collector = WindowsEventLogCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_events_collector(self):
        """Test du collecteur d'événements."""
        collector = WindowsEventCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_files_collector(self):
        """Test du collecteur de fichiers."""
        collector = WindowsFileCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_network_collector(self):
        """Test du collecteur réseau."""
        collector = WindowsNetworkCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_processes_collector(self):
        """Test du collecteur de processus."""
        collector = WindowsProcessCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_registry_collector(self):
        """Test du collecteur de registre."""
        collector = WindowsRegistryCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_services_collector(self):
        """Test du collecteur de services."""
        collector = WindowsServiceCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_users_collector(self):
        """Test du collecteur d'utilisateurs."""
        collector = WindowsUserCollector()
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
    
    def test_privileges_check(self):
        """Test de la vérification des privilèges."""
        collector = WindowsCollector()
        self.mock_win32security.return_value = True
        self.assertTrue(collector._check_privileges())
    
    def test_system_info(self):
        """Test de la récupération des informations système."""
        collector = WindowsCollector()
        self.mock_win32api.return_value = 1920
        info = collector._get_system_info()
        self.assertIsInstance(info, dict)
        self.assertIn('resolution', info)
    
    def test_file_info(self):
        """Test de la récupération des informations de fichier."""
        collector = WindowsCollector()
        self.mock_win32file.return_value = 32
        info = collector._get_file_info('test.txt')
        self.assertIsInstance(info, dict)
        self.assertIn('attributes', info)

if __name__ == '__main__':
    unittest.main() 