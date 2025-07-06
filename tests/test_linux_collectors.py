"""
Tests pour les collecteurs Linux.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
from pathlib import Path

if not sys.platform.startswith('linux'):
    import pytest
    pytest.skip('Tests Linux ignorés sur plateforme non-Linux', allow_module_level=True)

# Import des modules Linux
from collectors.linux import (
    LinuxCollector,
    LinuxAuthLogCollector,
    LinuxCronJobsCollector,
    LinuxFileCollector,
    LinuxNetworkCollector,
    LinuxNetworkConnectionsCollector,
    LinuxProcessCollector,
    LinuxServiceCollector,
    LinuxShellHistoryCollector,
    LinuxSystemLogCollector,
    LinuxSystemdServiceCollector,
    LinuxUserCollector
)

class TestLinuxCollectors(unittest.TestCase):
    """Tests pour les collecteurs Linux."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        # Mocks pour les fonctions système
        self.mock_subprocess = patch('subprocess.run').start()
        self.mock_os_path = patch('os.path.exists').start()
        self.mock_glob = patch('glob.glob').start()
        self.mock_open = patch('builtins.open', mock_open()).start()
        self.mock_pwd = patch('pwd.getpwall').start()
        self.mock_grp = patch('grp.getgrall').start()
        self.mock_psutil = patch('psutil.process_iter').start()
        self.mock_psutil_net = patch('psutil.net_connections').start()
        self.mock_psutil_cpu = patch('psutil.cpu_percent').start()
        self.mock_psutil_memory = patch('psutil.virtual_memory').start()
        self.mock_psutil_disk = patch('psutil.disk_usage').start()
        
        # Configuration des mocks
        self.mock_os_path.return_value = True
        self.mock_glob.return_value = ['/test/file']
        
    def tearDown(self):
        """Nettoyage après les tests."""
        patch.stopall()
    
    def test_linux_collector_base(self):
        """Test du collecteur de base Linux."""
        collector = LinuxCollector()
        self.assertIsInstance(collector, LinuxCollector)
        self.assertTrue(hasattr(collector, 'collect'))
    
    def test_linux_collector_get_system_info(self):
        """Test de la récupération des informations système."""
        collector = LinuxCollector()
        
        # Mock subprocess.run
        mock_result = MagicMock()
        mock_result.stdout = b'Linux test-host 5.4.0-generic #1 SMP x86_64'
        mock_result.returncode = 0
        self.mock_subprocess.return_value = mock_result
        
        result = collector.get_system_info()
        self.assertIsInstance(result, dict)
        self.assertIn('hostname', result)
        self.assertIn('os_version', result)
    
    def test_linux_collector_get_system_info_exception(self):
        """Test de la récupération des informations système avec exception."""
        collector = LinuxCollector()
        self.mock_subprocess.side_effect = Exception("Test exception")
        
        result = collector.get_system_info()
        self.assertEqual(result, {})
    
    def test_linux_collector_get_file_info(self):
        """Test de la récupération des informations de fichier."""
        collector = LinuxCollector()
        
        # Mock os.stat
        mock_stat = MagicMock()
        mock_stat.st_size = 1024
        mock_stat.st_ctime = 1609459200
        mock_stat.st_mtime = 1609459200
        mock_stat.st_atime = 1609459200
        mock_stat.st_mode = 0o644
        mock_stat.st_uid = 1000
        mock_stat.st_gid = 1000
        
        with patch('os.stat', return_value=mock_stat):
            with patch('pwd.getpwuid') as mock_pwd_getpwuid:
                with patch('grp.getgrgid') as mock_grp_getgrgid:
                    mock_pwd_getpwuid.return_value = MagicMock(pw_name='testuser')
                    mock_grp_getgrgid.return_value = MagicMock(gr_name='testgroup')
                    
                    result = collector.get_file_info('/test/file')
                    self.assertIsInstance(result, dict)
                    self.assertIn('path', result)
                    self.assertIn('size', result)
                    self.assertIn('owner', result)
                    self.assertIn('group', result)
    
    def test_linux_collector_get_file_info_exception(self):
        """Test de la récupération des informations de fichier avec exception."""
        collector = LinuxCollector()
        
        with patch('os.stat', side_effect=Exception("Test exception")):
            result = collector.get_file_info('/test/file')
            self.assertEqual(result, {})
    
    def test_linux_auth_log_collector(self):
        """Test du collecteur de logs d'authentification."""
        collector = LinuxAuthLogCollector()
        
        # Mock le contenu du fichier auth.log
        mock_content = """
Jan  1 12:00:00 test-host sshd[1234]: Accepted password for testuser from 192.168.1.1
Jan  1 12:01:00 test-host sshd[1235]: Failed password for invalid user admin from 192.168.1.2
Jan  1 12:02:00 test-host sudo: testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/bin/ls
"""
        
        with patch('builtins.open', mock_open(read_data=mock_content)):
            result = collector.collect()
            self.assertIsInstance(result, dict)
            self.assertIn('timestamp', result)
            self.assertIn('auth_events', result)
    
    def test_linux_cron_jobs_collector(self):
        """Test du collecteur de tâches cron."""
        collector = LinuxCronJobsCollector()
        
        # Mock subprocess.run pour crontab
        mock_result = MagicMock()
        mock_result.stdout = b'0 12 * * * /usr/bin/backup.sh\n30 2 * * 0 /usr/bin/cleanup.sh'
        mock_result.returncode = 0
        self.mock_subprocess.return_value = mock_result
        
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('cron_jobs', result)
    
    def test_linux_file_collector(self):
        """Test du collecteur de fichiers."""
        collector = LinuxFileCollector()
        
        # Mock os.walk
        with patch('os.walk') as mock_walk:
            mock_walk.return_value = [('/test', [], ['test.txt'])]
            
            # Mock os.stat
            mock_stat = MagicMock()
            mock_stat.st_size = 1024
            mock_stat.st_ctime = 1609459200
            mock_stat.st_mtime = 1609459200
            mock_stat.st_atime = 1609459200
            mock_stat.st_mode = 0o644
            mock_stat.st_uid = 1000
            mock_stat.st_gid = 1000
            
            with patch('os.stat', return_value=mock_stat):
                with patch('pwd.getpwuid') as mock_pwd_getpwuid:
                    with patch('grp.getgrgid') as mock_grp_getgrgid:
                        mock_pwd_getpwuid.return_value = MagicMock(pw_name='testuser')
                        mock_grp_getgrgid.return_value = MagicMock(gr_name='testgroup')
                        
                        result = collector.collect()
                        self.assertIsInstance(result, dict)
                        self.assertIn('timestamp', result)
                        self.assertIn('files', result)
    
    def test_linux_network_collector(self):
        """Test du collecteur réseau."""
        collector = LinuxNetworkCollector()
        
        # Mock subprocess.run pour les commandes réseau
        mock_result = MagicMock()
        mock_result.stdout = b'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0'
        mock_result.returncode = 0
        self.mock_subprocess.return_value = mock_result
        
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('network_interfaces', result)
    
    def test_linux_network_connections_collector(self):
        """Test du collecteur de connexions réseau."""
        collector = LinuxNetworkConnectionsCollector()
        
        # Mock psutil.net_connections
        mock_connections = [
            MagicMock(
                laddr=('127.0.0.1', 8080),
                raddr=('192.168.1.1', 80),
                status='ESTABLISHED',
                pid=1234
            )
        ]
        self.mock_psutil_net.return_value = mock_connections
        
        with patch('psutil.Process') as mock_process:
            mock_process_instance = MagicMock()
            mock_process_instance.name.return_value = "test.exe"
            mock_process.return_value = mock_process_instance
            
            result = collector.collect()
            self.assertIsInstance(result, dict)
            self.assertIn('timestamp', result)
            self.assertIn('connections', result)
    
    def test_linux_process_collector(self):
        """Test du collecteur de processus."""
        collector = LinuxProcessCollector()
        
        # Mock psutil.process_iter
        mock_processes = [
            MagicMock(
                pid=1234,
                name=lambda: "test",
                cmdline=lambda: ["test", "--arg"],
                create_time=lambda: 1609459200.0,
                memory_info=lambda: MagicMock(rss=1024*1024),
                cpu_percent=lambda: 5.0,
                status=lambda: "running"
            )
        ]
        self.mock_psutil.return_value = mock_processes
        
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('processes', result)
    
    def test_linux_service_collector(self):
        """Test du collecteur de services."""
        collector = LinuxServiceCollector()
        
        # Mock subprocess.run pour systemctl
        mock_result = MagicMock()
        mock_result.stdout = b'ssh.service - OpenBSD Secure Shell server\n   Loaded: loaded (/lib/systemd/system/ssh.service; enabled)'
        mock_result.returncode = 0
        self.mock_subprocess.return_value = mock_result
        
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('services', result)
    
    def test_linux_shell_history_collector(self):
        """Test du collecteur d'historique shell."""
        collector = LinuxShellHistoryCollector()
        
        # Mock le contenu du fichier .bash_history
        mock_content = """
ls -la
cd /home
ps aux
"""
        
        with patch('builtins.open', mock_open(read_data=mock_content)):
            result = collector.collect()
            self.assertIsInstance(result, dict)
            self.assertIn('timestamp', result)
            self.assertIn('shell_history', result)
    
    def test_linux_system_log_collector(self):
        """Test du collecteur de logs système."""
        collector = LinuxSystemLogCollector()
        
        # Mock le contenu du fichier syslog
        mock_content = """
Jan  1 12:00:00 test-host kernel: [    0.000000] Linux version 5.4.0-generic
Jan  1 12:00:01 test-host systemd[1]: Starting systemd 245.4-4ubuntu3.2
Jan  1 12:00:02 test-host systemd[1]: Started systemd 245.4-4ubuntu3.2
"""
        
        with patch('builtins.open', mock_open(read_data=mock_content)):
            result = collector.collect()
            self.assertIsInstance(result, dict)
            self.assertIn('timestamp', result)
            self.assertIn('system_logs', result)
    
    def test_linux_systemd_service_collector(self):
        """Test du collecteur de services systemd."""
        collector = LinuxSystemdServiceCollector()
        
        # Mock subprocess.run pour systemctl
        mock_result = MagicMock()
        mock_result.stdout = b'ssh.service - OpenBSD Secure Shell server\n   Loaded: loaded (/lib/systemd/system/ssh.service; enabled)'
        mock_result.returncode = 0
        self.mock_subprocess.return_value = mock_result
        
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('systemd_services', result)
    
    def test_linux_user_collector(self):
        """Test du collecteur d'utilisateurs."""
        collector = LinuxUserCollector()
        
        # Mock pwd.getpwall
        mock_users = [
            MagicMock(
                pw_name='testuser',
                pw_passwd='x',
                pw_uid=1000,
                pw_gid=1000,
                pw_gecos='Test User',
                pw_dir='/home/testuser',
                pw_shell='/bin/bash'
            )
        ]
        self.mock_pwd.return_value = mock_users
        
        # Mock grp.getgrall
        mock_groups = [
            MagicMock(
                gr_name='testgroup',
                gr_passwd='x',
                gr_gid=1000,
                gr_mem=['testuser']
            )
        ]
        self.mock_grp.return_value = mock_groups
        
        result = collector.collect()
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('users', result)
        self.assertIn('groups', result)

if __name__ == '__main__':
    unittest.main() 