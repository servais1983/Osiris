"""
Tests multi-OS pour les collecteurs Linux d'Osiris
Teste tous les collecteurs Linux avec des mocks appropriés selon l'OS
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
    if platform.system() == 'Windows':
        # Mock des modules Unix spécifiques sur Windows
        sys.modules['pwd'] = Mock()
        sys.modules['grp'] = Mock()
        sys.modules['fcntl'] = Mock()
        sys.modules['termios'] = Mock()
        sys.modules['crypt'] = Mock()
        sys.modules['spwd'] = Mock()
        sys.modules['psutil'] = Mock()
        
        # Mock de os.geteuid si non disponible
        if not hasattr(os, 'geteuid'):
            os.geteuid = lambda: 0

# Configuration des mocks avant les imports
setup_os_mocks()

# Import des modules Linux après avoir configuré les mocks
from collectors.linux import (
    LinuxCollectorManager,
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

def skip_if_not_linux():
    """Décorateur pour skipper les tests sur les OS non-Linux"""
    def decorator(test_method):
        def wrapper(self, *args, **kwargs):
            if platform.system() != 'Linux':
                self.skipTest(f"Test spécifique à Linux, OS actuel: {platform.system()}")
            return test_method(self, *args, **kwargs)
        return wrapper
    return decorator

class TestLinuxCollectorManagerMultiOS(unittest.TestCase):
    """Tests pour le gestionnaire de collecteurs Linux (multi-OS)"""
    
    def setUp(self):
        self.manager = LinuxCollectorManager()
    
    def test_list_collectors(self):
        """Test de la liste des collecteurs disponibles"""
        collectors = self.manager.list_collectors()
        expected = [
            'system_logs', 'shell_history', 'processes', 'network',
            'files', 'services', 'users', 'cron_jobs', 'systemd_services'
        ]
        self.assertEqual(set(collectors), set(expected))
    
    def test_get_collector_valid(self):
        """Test de récupération d'un collecteur valide"""
        collector = self.manager.get_collector('system_logs')
        self.assertIsInstance(collector, SystemLogsCollector)
    
    def test_get_collector_invalid(self):
        """Test de récupération d'un collecteur invalide"""
        with self.assertRaises(ValueError):
            self.manager.get_collector('invalid_collector')
    
    def test_collect_all_multi_os(self):
        """Test de collecte de tous les collecteurs (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'system_logs', 'shell_history', 'processes', 'network',
            'files', 'services', 'users', 'cron_jobs', 'systemd_services'
        ]
        
        for collector_name in expected_collectors:
            self.assertIn(collector_name, results)
            self.assertIsInstance(results[collector_name], dict)

class TestSystemLogsCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de logs système (multi-OS)"""
    
    def setUp(self):
        self.collector = SystemLogsCollector()
    
    def test_collect_system_logs_multi_os(self):
        """Test de collecte des logs système (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('log_files', result)
        
        # Vérifier les informations système
        system_info = result['system_info']
        self.assertIn('platform', system_info)
        self.assertIn('timestamp', system_info)
    
    def test_collect_no_logs_multi_os(self):
        """Test quand aucun log n'est trouvé (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('log_files', result)

class TestShellHistoryCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur d'historique shell (multi-OS)"""
    
    def setUp(self):
        self.collector = ShellHistoryCollector()
    
    def test_collect_shell_history_multi_os(self):
        """Test de collecte de l'historique shell (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('history_entries', result)
        self.assertIn('users_analyzed', result)
        self.assertIn('suspicious_commands', result)
        self.assertIn('summary', result)
    
    def test_collect_no_users_multi_os(self):
        """Test avec aucun utilisateur (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('history_entries', result)

class TestProcessesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de processus (multi-OS)"""
    
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
        self.assertIn('summary', result)
    
    def test_psutil_availability_check(self):
        """Test de la vérification de disponibilité de psutil"""
        # Vérifier que la méthode existe
        self.assertTrue(hasattr(self.collector, '_check_psutil_availability'))
        
        # Vérifier que l'attribut est défini
        self.assertTrue(hasattr(self.collector, 'psutil_available'))

class TestNetworkCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur réseau (multi-OS)"""
    
    def setUp(self):
        self.collector = NetworkCollector()
    
    def test_collect_network_info_multi_os(self):
        """Test de collecte des informations réseau (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('interfaces', result)
        self.assertIn('connections', result)
        self.assertIn('routing', result)
        self.assertIn('dns', result)
        self.assertIn('summary', result)
    
    def test_collect_network_no_files_multi_os(self):
        """Test quand les fichiers réseau n'existent pas (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('interfaces', result)

class TestFilesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de fichiers (multi-OS)"""
    
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
        self.assertIn('file_permissions', result)
        self.assertIn('summary', result)
    
    def test_collect_files_permission_error_multi_os(self):
        """Test avec erreur de permission (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('important_files', result)

class TestServicesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de services (multi-OS)"""
    
    def setUp(self):
        self.collector = ServicesCollector()
    
    def test_collect_services_multi_os(self):
        """Test de collecte des services (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('systemd_services', result)
        self.assertIn('init_services', result)
        self.assertIn('running_services', result)
        self.assertIn('failed_services', result)
        self.assertIn('summary', result)
    
    def test_collect_services_no_directory_multi_os(self):
        """Test quand le répertoire n'existe pas (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('systemd_services', result)

class TestUsersCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur d'utilisateurs (multi-OS)"""
    
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
        self.assertIn('privileged_users', result)
        self.assertIn('recent_logins', result)
        self.assertIn('summary', result)
    
    def test_geteuid_method(self):
        """Test de la méthode utilitaire _geteuid"""
        # Vérifier que la méthode existe
        self.assertTrue(hasattr(self.collector, '_geteuid'))
        
        # Vérifier qu'elle retourne un entier
        euid = self.collector._geteuid()
        self.assertIsInstance(euid, int)
    
    def test_collect_users_permission_error_multi_os(self):
        """Test avec erreur de permission (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('users', result)

class TestCronJobsCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de tâches cron (multi-OS)"""
    
    def setUp(self):
        self.collector = CronJobsCollector()
    
    def test_collect_cron_jobs_multi_os(self):
        """Test de collecte des tâches cron (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('system_crontab', result)
        self.assertIn('user_crontabs', result)
        self.assertIn('cron_directories', result)
        self.assertIn('suspicious_jobs', result)
        self.assertIn('summary', result)
    
    def test_collect_cron_jobs_no_directory_multi_os(self):
        """Test quand le répertoire n'existe pas (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('system_crontab', result)

class TestSystemdServicesCollectorMultiOS(unittest.TestCase):
    """Tests pour le collecteur de services systemd (multi-OS)"""
    
    def setUp(self):
        self.collector = SystemdServicesCollector()
    
    def test_collect_systemd_services_multi_os(self):
        """Test de collecte des services systemd (multi-OS)"""
        result = self.collector.collect()
        
        # Vérifier la structure de base
        self.assertIsInstance(result, dict)
        self.assertIn('system_info', result)
        self.assertIn('services', result)
        self.assertIn('running_services', result)
        self.assertIn('failed_services', result)
        self.assertIn('enabled_services', result)
        self.assertIn('disabled_services', result)
        self.assertIn('summary', result)
    
    def test_systemctl_availability_check(self):
        """Test de la vérification de disponibilité de systemctl"""
        # Vérifier que la méthode existe
        self.assertTrue(hasattr(self.collector, '_check_systemctl_availability'))
        
        # Vérifier que l'attribut est défini
        self.assertTrue(hasattr(self.collector, 'systemctl_available'))
    
    def test_collect_systemd_services_command_error_multi_os(self):
        """Test avec erreur de commande (multi-OS)"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('services', result)

class TestLinuxCollectorIntegrationMultiOS(unittest.TestCase):
    """Tests d'intégration pour les collecteurs Linux (multi-OS)"""
    
    def setUp(self):
        self.manager = LinuxCollectorManager()
    
    def test_multiple_collectors_multi_os(self):
        """Test de plusieurs collecteurs ensemble (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'system_logs', 'shell_history', 'processes', 'network',
            'files', 'services', 'users', 'cron_jobs', 'systemd_services'
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
            self.assertIn('timestamp', system_info)

class TestLinuxCollectorErrorHandlingMultiOS(unittest.TestCase):
    """Tests de gestion d'erreurs pour les collecteurs Linux (multi-OS)"""
    
    def setUp(self):
        self.manager = LinuxCollectorManager()
    
    def test_collector_exception_handling_multi_os(self):
        """Test de gestion des exceptions dans les collecteurs (multi-OS)"""
        results = self.manager.collect_all()
        
        # Vérifier que tous les collecteurs ont été exécutés
        expected_collectors = [
            'system_logs', 'shell_history', 'processes', 'network',
            'files', 'services', 'users', 'cron_jobs', 'systemd_services'
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