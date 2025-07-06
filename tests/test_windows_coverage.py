"""
Tests ciblés pour améliorer la couverture des modules Windows.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import time
from pathlib import Path

from collectors.windows.event_logs import WindowsEventLogCollector
from collectors.windows.events import WindowsEventCollector
from collectors.windows.services import WindowsServiceCollector
from collectors.windows.users import WindowsUserCollector
from collectors.windows.files import WindowsFileCollector
from collectors.windows.network import WindowsNetworkCollector
from collectors.windows.processes import WindowsProcessCollector
from collectors.windows.registry import WindowsRegistryCollector

class TestWindowsCoverage(unittest.TestCase):
    """Tests ciblés pour améliorer la couverture des modules Windows."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        pass
        
    def tearDown(self):
        """Nettoyage après les tests."""
        patch.stopall()
    
    def test_event_logs_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur de journaux d'événements."""
        collector = WindowsEventLogCollector()
        
        # Mock la vérification des privilèges
        with patch.object(collector, 'check_privileges', return_value=True):
            # Test de la méthode _get_event_type
            result = collector._get_event_type(1)  # ERROR
            self.assertEqual(result, 'Error')
            
            result = collector._get_event_type(2)  # WARNING
            self.assertEqual(result, 'Warning')
            
            result = collector._get_event_type(4)  # INFORMATION
            self.assertEqual(result, 'Information')
            
            result = collector._get_event_type(8)  # AUDIT_SUCCESS
            self.assertEqual(result, 'Audit Success')
            
            result = collector._get_event_type(16)  # AUDIT_FAILURE
            self.assertEqual(result, 'Audit Failure')
            
            result = collector._get_event_type(999)  # UNKNOWN
            self.assertEqual(result, 'Unknown')
            
            # Test de la méthode _get_event_severity
            result = collector._get_event_severity(1)  # ERROR
            self.assertEqual(result, 'High')
            
            result = collector._get_event_severity(2)  # WARNING
            self.assertEqual(result, 'Medium')
            
            result = collector._get_event_severity(4)  # INFORMATION
            self.assertEqual(result, 'Info')
            
            result = collector._get_event_severity(8)  # AUDIT_SUCCESS
            self.assertEqual(result, 'Low')
            
            result = collector._get_event_severity(16)  # AUDIT_FAILURE
            self.assertEqual(result, 'High')
            
            # Test de la méthode _get_event_data
            mock_event = MagicMock()
            mock_event.Data = b'test_data'
            result = collector._get_event_data(mock_event)
            self.assertIsInstance(result, dict)
            self.assertIn('raw_data', result)
            
            # Test avec exception
            mock_event.Data = None
            result = collector._get_event_data(mock_event)
            self.assertIsInstance(result, dict)
            self.assertIn('raw_data', result)
            
            # Test de la méthode _get_user_sid
            mock_event = MagicMock()
            mock_event.UserSid = MagicMock()
            
            with patch('win32security.ConvertSidToStringSid') as mock_convert:
                mock_convert.return_value = "S-1-5-21-1234567890-1234567890-1234567890-1000"
                result = collector._get_user_sid(mock_event)
                self.assertEqual(result, "S-1-5-21-1234567890-1234567890-1234567890-1000")
            
            # Test avec exception
            with patch('win32security.ConvertSidToStringSid') as mock_convert:
                mock_convert.side_effect = Exception("SID error")
                result = collector._get_user_sid(mock_event)
                self.assertIsNone(result)
            
            # Test avec UserSid None
            mock_event.UserSid = None
            result = collector._get_user_sid(mock_event)
            self.assertIsNone(result)
    
    def test_events_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur d'événements."""
        collector = WindowsEventCollector()
        
        # Mock la vérification des privilèges
        with patch.object(collector, 'check_privileges', return_value=True):
            # Test de la méthode _get_event_binary_data
            mock_event = MagicMock()
            mock_event.Data = b'\x01\x02\x03\x04'
            result = collector._get_event_binary_data(mock_event)
            self.assertEqual(result, [1, 2, 3, 4])
            
            # Test avec exception
            mock_event.Data = None
            result = collector._get_event_binary_data(mock_event)
            self.assertEqual(result, [])
            
            # Test de la méthode _get_event_string_data
            mock_event.StringInserts = ['string1', 'string2']
            result = collector._get_event_string_data(mock_event)
            self.assertEqual(result, ['string1', 'string2'])
            
            # Test avec exception
            mock_event.StringInserts = None
            result = collector._get_event_string_data(mock_event)
            self.assertEqual(result, [])
            
            # Test de la méthode _get_event_category_data
            mock_event.CategoryStrings = ['cat1', 'cat2']
            result = collector._get_event_category_data(mock_event)
            self.assertEqual(result, ['cat1', 'cat2'])
            
            # Test avec exception
            mock_event.CategoryStrings = None
            result = collector._get_event_category_data(mock_event)
            self.assertEqual(result, [])
            
            # Test de la méthode _get_event_type
            result = collector._get_event_type(1)  # ERROR
            self.assertEqual(result, 'ERROR')
            
            result = collector._get_event_type(2)  # WARNING
            self.assertEqual(result, 'WARNING')
            
            result = collector._get_event_type(4)  # INFORMATION
            self.assertEqual(result, 'INFORMATION')
            
            result = collector._get_event_type(8)  # AUDIT_SUCCESS
            self.assertEqual(result, 'AUDIT_SUCCESS')
            
            result = collector._get_event_type(16)  # AUDIT_FAILURE
            self.assertEqual(result, 'AUDIT_FAILURE')
            
            result = collector._get_event_type(999)  # UNKNOWN
            self.assertEqual(result, 'UNKNOWN')
            
            # Test de la méthode _get_event_user_sid
            mock_event = MagicMock()
            mock_event.UserSid = MagicMock()
            
            with patch('win32security.ConvertSidToStringSid') as mock_convert:
                mock_convert.return_value = "S-1-5-21-1234567890-1234567890-1234567890-1000"
                
                with patch('win32security.LookupAccountSid') as mock_lookup:
                    mock_lookup.return_value = ("testuser", "testdomain", 1)
                    
                    result = collector._get_event_user_sid(mock_event)
                    self.assertIsInstance(result, dict)
                    self.assertEqual(result['sid'], "S-1-5-21-1234567890-1234567890-1234567890-1000")
                    self.assertEqual(result['name'], "testuser")
            
            # Test avec UserSid None
            mock_event.UserSid = None
            result = collector._get_event_user_sid(mock_event)
            self.assertIsNone(result)
            
            # Test avec exception
            mock_event.UserSid = MagicMock()
            with patch('win32security.ConvertSidToStringSid') as mock_convert:
                mock_convert.side_effect = Exception("SID error")
                result = collector._get_event_user_sid(mock_event)
                self.assertIsNone(result)
    
    def test_files_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur de fichiers."""
        collector = WindowsFileCollector()
        
        # Mock la vérification des privilèges
        with patch.object(collector, 'check_privileges', return_value=True):
            # Test de la méthode _get_file_attributes
            result = collector._get_file_attributes(32)  # Normal file
            self.assertIsInstance(result, list)
            
            result = collector._get_file_attributes(1)  # Read-only
            self.assertIsInstance(result, list)
            
            result = collector._get_file_attributes(2)  # Hidden
            self.assertIsInstance(result, list)
            
            # Test de la méthode _get_ace_type
            result = collector._get_ace_type(0)  # ACCESS_ALLOWED
            self.assertEqual(result, 'ACCESS_ALLOWED')
            
            result = collector._get_ace_type(1)  # ACCESS_DENIED
            self.assertEqual(result, 'ACCESS_DENIED')
            
            result = collector._get_ace_type(2)  # SYSTEM_AUDIT
            self.assertEqual(result, 'SYSTEM_AUDIT')
            
            result = collector._get_ace_type(999)  # UNKNOWN
            self.assertEqual(result, 'UNKNOWN')
            
            # Test de la méthode _get_ace_flags
            result = collector._get_ace_flags(1)  # OBJECT_INHERIT_ACE
            self.assertIsInstance(result, list)
            
            result = collector._get_ace_flags(2)  # CONTAINER_INHERIT_ACE
            self.assertIsInstance(result, list)
    
    def test_network_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur réseau."""
        collector = WindowsNetworkCollector()
        
        # Mock la vérification des privilèges
        with patch.object(collector, 'check_privileges', return_value=True):
            # Test de la méthode _get_network_interfaces
            with patch('psutil.net_if_addrs') as mock_addrs:
                mock_addrs.return_value = {
                    'Ethernet': [
                        MagicMock(
                            family=2,  # AF_INET
                            address='192.168.1.1',
                            netmask='255.255.255.0'
                        )
                    ]
                }
                
                result = collector._get_network_interfaces()
                self.assertIsInstance(result, list)
            
            # Test de la méthode _get_tcp_connections
            with patch('psutil.net_connections') as mock_connections:
                mock_connections.return_value = [
                    MagicMock(
                        laddr=('127.0.0.1', 8080),
                        raddr=('192.168.1.1', 80),
                        status='ESTABLISHED',
                        type=1  # SOCK_STREAM
                    )
                ]
                
                result = collector._get_tcp_connections()
                self.assertIsInstance(result, list)
    
    def test_processes_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur de processus."""
        collector = WindowsProcessCollector()
        
        # Mock la vérification des privilèges
        with patch.object(collector, 'check_privileges', return_value=True):
            # Test de la méthode _get_process_info
            mock_process = MagicMock()
            mock_process.pid = 1234
            mock_process.name.return_value = "test.exe"
            mock_process.cmdline.return_value = ["test.exe", "--arg"]
            mock_process.create_time.return_value = 1609459200.0
            mock_process.memory_info.return_value = MagicMock(rss=1024*1024)
            mock_process.cpu_percent.return_value = 5.0
            mock_process.status.return_value = "running"
            
            result = collector._get_process_info(mock_process)
            self.assertIsInstance(result, dict)
            self.assertEqual(result['pid'], 1234)
            self.assertEqual(result['name'], "test.exe")
    
    def test_registry_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur de registre."""
        collector = WindowsRegistryCollector()
        
        # Mock la vérification des privilèges
        with patch.object(collector, 'check_privileges', return_value=True):
            # Test de la méthode _get_value_type
            result = collector._get_value_type(1)  # REG_SZ
            self.assertEqual(result, 'REG_SZ')
            
            result = collector._get_value_type(2)  # REG_EXPAND_SZ
            self.assertEqual(result, 'REG_EXPAND_SZ')
            
            result = collector._get_value_type(3)  # REG_BINARY
            self.assertEqual(result, 'REG_BINARY')
            
            result = collector._get_value_type(4)  # REG_DWORD
            self.assertEqual(result, 'REG_DWORD_LITTLE_ENDIAN')
            
            result = collector._get_value_type(7)  # REG_MULTI_SZ
            self.assertEqual(result, 'REG_MULTI_SZ')
            
            result = collector._get_value_type(11)  # REG_QWORD
            self.assertEqual(result, 'REG_QWORD_LITTLE_ENDIAN')
            
            result = collector._get_value_type(999)  # UNKNOWN
            self.assertEqual(result, 'UNKNOWN')
            
            # Test de la méthode _format_value
            result = collector._format_value("test_value", 1)  # REG_SZ
            self.assertEqual(result, "test_value")
            
            result = collector._format_value(b'\x01\x02\x03', 3)  # REG_BINARY
            self.assertEqual(result, ['0x1', '0x2', '0x3'])
            
            result = collector._format_value(12345, 4)  # REG_DWORD
            self.assertEqual(result, 12345)
            
            result = collector._format_value(["str1", "str2"], 7)  # REG_MULTI_SZ
            self.assertEqual(result, ["str1", "str2"])
            
            result = collector._format_value(123456789, 11)  # REG_QWORD
            self.assertEqual(result, 123456789)
            
            result = collector._format_value("unknown", 999)  # UNKNOWN
            self.assertEqual(result, "unknown")

if __name__ == '__main__':
    unittest.main() 