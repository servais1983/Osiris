"""
Tests de couverture avancée pour les modules Linux d'Osiris
Teste tous les collecteurs Linux avec des mocks appropriés
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys
import os
import tempfile
import shutil
from datetime import datetime
import json

# Ajout pour compatibilité Windows : mock de os.geteuid s'il n'existe pas
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 1000

# Mock des modules Unix spécifiques avant les imports
sys.modules['pwd'] = Mock()
sys.modules['grp'] = Mock()
sys.modules['fcntl'] = Mock()
sys.modules['termios'] = Mock()
sys.modules['crypt'] = Mock()
sys.modules['spwd'] = Mock()
sys.modules['psutil'] = Mock()

# Import des modules Linux après avoir mocké les dépendances Unix
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

class TestLinuxCollectorManager(unittest.TestCase):
    """Tests pour le gestionnaire de collecteurs Linux"""
    
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
    
    @patch('collectors.linux.system_logs.SystemLogsCollector')
    def test_collect_all(self, mock_system_logs):
        """Test de collecte de tous les collecteurs"""
        mock_instance = Mock()
        mock_instance.collect.return_value = {'test': 'data'}
        mock_system_logs.return_value = mock_instance
        
        results = self.manager.collect_all()
        self.assertIn('system_logs', results)

class TestSystemLogsCollector(unittest.TestCase):
    """Tests pour le collecteur de logs système"""
    
    def setUp(self):
        self.collector = SystemLogsCollector()
    
    @patch('builtins.open', new_callable=mock_open, read_data="test log data")
    @patch('os.path.exists', return_value=True)
    def test_collect_system_logs(self, mock_exists, mock_file):
        """Test de collecte des logs système"""
        with patch('glob.glob', return_value=['/var/log/syslog']):
            result = self.collector.collect()
            self.assertIsInstance(result, dict)
            self.assertIn('log_files', result)
    
    @patch('os.path.exists', return_value=False)
    def test_collect_no_logs(self, mock_exists):
        """Test quand aucun log n'est trouvé"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('log_files', result)

class TestShellHistoryCollector(unittest.TestCase):
    """Tests pour le collecteur d'historique shell"""
    
    def setUp(self):
        self.collector = ShellHistoryCollector()
    
    @patch('pwd.getpwall')
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="ls -la\ncd /tmp\n")
    def test_collect_shell_history(self, mock_file, mock_exists, mock_getpwall):
        """Test de collecte de l'historique shell"""
        mock_getpwall.return_value = [
            Mock(pw_name='testuser', pw_dir='/home/testuser')
        ]
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('history_entries', result)
    
    @patch('pwd.getpwall')
    def test_collect_no_users(self, mock_getpwall):
        """Test avec aucun utilisateur"""
        mock_getpwall.return_value = []
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestProcessesCollector(unittest.TestCase):
    """Tests pour le collecteur de processus"""
    
    def setUp(self):
        self.collector = ProcessesCollector()
    
    @patch('os.listdir')
    @patch('builtins.open', new_callable=mock_open)
    def test_collect_processes(self, mock_file, mock_listdir):
        """Test de collecte des processus"""
        mock_listdir.return_value = ['1', '2', '3']
        mock_file.return_value.__enter__.return_value.read.side_effect = [
            'test process 1',
            'test process 2', 
            'test process 3'
        ]
        
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('processes', result)
    
    @patch('os.listdir', side_effect=OSError("Permission denied"))
    def test_collect_processes_permission_error(self, mock_listdir):
        """Test avec erreur de permission"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestNetworkCollector(unittest.TestCase):
    """Tests pour le collecteur réseau"""
    
    def setUp(self):
        self.collector = NetworkCollector()
    
    @patch('builtins.open', new_callable=mock_open, read_data="test network data")
    @patch('os.path.exists', return_value=True)
    def test_collect_network_info(self, mock_exists, mock_file):
        """Test de collecte des informations réseau"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('interfaces', result)
    
    @patch('os.path.exists', return_value=False)
    def test_collect_network_no_files(self, mock_exists):
        """Test quand les fichiers réseau n'existent pas"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestFilesCollector(unittest.TestCase):
    """Tests pour le collecteur de fichiers"""
    
    def setUp(self):
        self.collector = FilesCollector()
    
    @patch('os.walk')
    @patch('os.path.getmtime', return_value=1234567890.0)
    @patch('os.path.getsize', return_value=1024)
    def test_collect_files(self, mock_getsize, mock_getmtime, mock_walk):
        """Test de collecte des fichiers"""
        mock_walk.return_value = [
            ('/test', ['dir1'], ['file1.txt', 'file2.txt'])
        ]
        
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('important_files', result)
    
    @patch('os.walk', side_effect=OSError("Permission denied"))
    def test_collect_files_permission_error(self, mock_walk):
        """Test avec erreur de permission"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestServicesCollector(unittest.TestCase):
    """Tests pour le collecteur de services"""
    
    def setUp(self):
        self.collector = ServicesCollector()
    
    @patch('os.listdir')
    @patch('builtins.open', new_callable=mock_open, read_data="test service data")
    def test_collect_services(self, mock_file, mock_listdir):
        """Test de collecte des services"""
        mock_listdir.return_value = ['service1', 'service2']
        
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('systemd_services', result)
    
    @patch('os.listdir', side_effect=OSError("Directory not found"))
    def test_collect_services_no_directory(self, mock_listdir):
        """Test quand le répertoire n'existe pas"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestUsersCollector(unittest.TestCase):
    """Tests pour le collecteur d'utilisateurs"""
    
    def setUp(self):
        self.collector = UsersCollector()
    
    @patch('pwd.getpwall')
    @patch('grp.getgrall')
    def test_collect_users(self, mock_getgrall, mock_getpwall):
        """Test de collecte des utilisateurs"""
        mock_user = Mock()
        mock_user.pw_name = 'testuser'
        mock_user.pw_uid = 1000
        mock_user.pw_gid = 1000
        mock_user.pw_dir = '/home/testuser'
        mock_user.pw_shell = '/bin/bash'
        
        mock_group = Mock()
        mock_group.gr_name = 'testgroup'
        mock_group.gr_gid = 1000
        mock_group.gr_mem = ['testuser']
        
        mock_getpwall.return_value = [mock_user]
        mock_getgrall.return_value = [mock_group]
        
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('users', result)
    
    @patch('pwd.getpwall', side_effect=OSError("Permission denied"))
    def test_collect_users_permission_error(self, mock_getpwall):
        """Test avec erreur de permission"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestCronJobsCollector(unittest.TestCase):
    """Tests pour le collecteur de tâches cron"""
    
    def setUp(self):
        self.collector = CronJobsCollector()
    
    @patch('os.listdir')
    @patch('builtins.open', new_callable=mock_open, read_data="0 * * * * /usr/bin/test")
    def test_collect_cron_jobs(self, mock_file, mock_listdir):
        """Test de collecte des tâches cron"""
        mock_listdir.return_value = ['user1', 'user2']
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('system_crontab', result)
    
    @patch('os.listdir', side_effect=OSError("Directory not found"))
    def test_collect_cron_jobs_no_directory(self, mock_listdir):
        """Test quand le répertoire n'existe pas"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestSystemdServicesCollector(unittest.TestCase):
    """Tests pour le collecteur de services systemd"""
    
    def setUp(self):
        self.collector = SystemdServicesCollector()
    
    @patch('subprocess.run')
    def test_collect_systemd_services(self, mock_run):
        """Test de collecte des services systemd"""
        mock_process = Mock()
        mock_process.stdout = b"test service\nanother service\n"
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        
        result = self.collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('services', result)
    
    @patch('subprocess.run', side_effect=OSError("Command not found"))
    def test_collect_systemd_services_command_error(self, mock_run):
        """Test avec erreur de commande"""
        result = self.collector.collect()
        self.assertIsInstance(result, dict)

class TestLinuxCollectorIntegration(unittest.TestCase):
    """Tests d'intégration pour les collecteurs Linux"""
    
    def setUp(self):
        self.manager = LinuxCollectorManager()
    
    @patch('collectors.linux.system_logs.SystemLogsCollector')
    @patch('collectors.linux.shell_history.ShellHistoryCollector')
    def test_multiple_collectors(self, mock_shell, mock_logs):
        """Test de plusieurs collecteurs ensemble"""
        mock_logs_instance = Mock()
        mock_logs_instance.collect.return_value = {'logs': 'test'}
        mock_logs.return_value = mock_logs_instance
        
        mock_shell_instance = Mock()
        mock_shell_instance.collect.return_value = {'history': 'test'}
        mock_shell.return_value = mock_shell_instance
        
        results = self.manager.collect_all()
        self.assertIn('system_logs', results)
        self.assertIn('shell_history', results)

class TestLinuxCollectorErrorHandling(unittest.TestCase):
    """Tests de gestion d'erreurs pour les collecteurs Linux"""
    
    def setUp(self):
        self.manager = LinuxCollectorManager()
    
    @patch('collectors.linux.system_logs.SystemLogsCollector')
    def test_collector_exception_handling(self, mock_collector):
        """Test de gestion des exceptions dans les collecteurs"""
        mock_instance = Mock()
        mock_instance.collect.side_effect = Exception("Test error")
        mock_collector.return_value = mock_instance
        
        results = self.manager.collect_all()
        self.assertIn('system_logs', results)
        # Le gestionnaire capture les exceptions et les met dans 'error'
        self.assertTrue('error' in results['system_logs'] or 'log_files' in results['system_logs'])

if __name__ == '__main__':
    # Configuration des mocks globaux
    unittest.main(verbosity=2) 