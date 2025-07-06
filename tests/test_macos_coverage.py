"""
Tests ciblés pour améliorer la couverture des modules macOS.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import time
from pathlib import Path

# Mock des modules Unix spécifiques avant les imports
import sys
from unittest.mock import MagicMock

# Mock des modules Unix
mock_pwd = MagicMock()
mock_plistlib = MagicMock()
mock_plistlib.InvalidFileException = type('InvalidFileException', (Exception,), {})

# Ajout des mocks au sys.modules
sys.modules['pwd'] = mock_pwd
sys.modules['plistlib'] = mock_plistlib

# Import des collecteurs macOS après avoir mocké les modules
from collectors.macos.unified_logs import MacUnifiedLogsCollector, UnifiedLogEntry
from collectors.macos.persistence import MacPersistenceCollector, PersistenceEntry

class TestMacOSCoverage(unittest.TestCase):
    """Tests ciblés pour améliorer la couverture des modules macOS."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        pass
        
    def tearDown(self):
        """Nettoyage après les tests."""
        patch.stopall()
    
    def test_unified_logs_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur de logs unifiés macOS."""
        collector = MacUnifiedLogsCollector()
        
        # Test de la création d'une entrée de log
        log_entry = UnifiedLogEntry(
            timestamp="2024-01-15 10:30:45.123456+0000",
            processImagePath="/usr/bin/kernel",
            senderImagePath="/System/Library/Frameworks/IOKit.framework/IOKit",
            subsystem="com.apple.iokit.IOAudioFamily",
            category="Audio",
            eventType="default",
            traceID="12345678-1234-1234-1234-123456789012",
            processID=1234,
            threadID=5678,
            message="Audio device started"
        )
        
        self.assertEqual(log_entry.timestamp, "2024-01-15 10:30:45.123456+0000")
        self.assertEqual(log_entry.processImagePath, "/usr/bin/kernel")
        self.assertEqual(log_entry.message, "Audio device started")
        self.assertEqual(log_entry.processID, 1234)
        
        # Test de la méthode collect avec mock
        mock_log_data = {
            "timestamp": "2024-01-15 10:30:45.123456+0000",
            "processImagePath": "/usr/bin/kernel",
            "senderImagePath": "/System/Library/Frameworks/IOKit.framework/IOKit",
            "subsystem": "com.apple.iokit.IOAudioFamily",
            "category": "Audio",
            "eventType": "default",
            "traceID": "12345678-1234-1234-1234-123456789012",
            "processID": 1234,
            "threadID": 5678,
            "eventMessage": "Audio device started"
        }
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.stdout = iter([json.dumps(mock_log_data)])
            mock_process.stderr = MagicMock()
            mock_process.stderr.read.return_value = ""
            mock_popen.return_value = mock_process
            
            entries = list(collector.collect())
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].message, "Audio device started")
            self.assertEqual(entries[0].processID, 1234)
        
        # Test avec erreur JSON
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.stdout = iter(['invalid json'])
            mock_process.stderr = MagicMock()
            mock_process.stderr.read.return_value = ""
            mock_popen.return_value = mock_process
            
            entries = list(collector.collect())
            self.assertEqual(len(entries), 0)
        
        # Test avec commande non trouvée
        with patch('subprocess.Popen', side_effect=FileNotFoundError("Command not found")):
            entries = list(collector.collect())
            self.assertEqual(len(entries), 0)
    
    def test_persistence_collector_coverage(self):
        """Test pour améliorer la couverture du collecteur de persistance macOS."""
        collector = MacPersistenceCollector()
        
        # Test de la création d'une entrée de persistance
        persistence_entry = PersistenceEntry(
            path="/Library/LaunchAgents/com.test.agent.plist",
            label="com.test.agent",
            program="/usr/bin/test",
            program_arguments=["/usr/bin/test", "--arg"],
            run_at_load=True,
            type="Global Agent"
        )
        
        self.assertEqual(persistence_entry.path, "/Library/LaunchAgents/com.test.agent.plist")
        self.assertEqual(persistence_entry.label, "com.test.agent")
        self.assertEqual(persistence_entry.program, "/usr/bin/test")
        self.assertEqual(persistence_entry.run_at_load, True)
        self.assertEqual(persistence_entry.type, "Global Agent")
        
        # Test de la méthode _parse_plist avec données valides
        mock_plist_data = {
            "Label": "com.test.agent",
            "ProgramArguments": ["/usr/bin/test", "--arg"],
            "RunAtLoad": True
        }
        
        with patch('builtins.open', mock_open()):
            with patch('plistlib.load') as mock_plist_load:
                mock_plist_load.return_value = mock_plist_data
                
                result = collector._parse_plist("/test/agent.plist", "Global Agent")
                self.assertIsInstance(result, PersistenceEntry)
                self.assertEqual(result.label, "com.test.agent")
                self.assertEqual(result.program_arguments, ["/usr/bin/test", "--arg"])
                self.assertEqual(result.run_at_load, True)
                self.assertEqual(result.type, "Global Agent")
        
        # Test avec plist invalide
        with patch('builtins.open', side_effect=Exception("File not found")):
            result = collector._parse_plist("/test/invalid.plist", "Global Agent")
            self.assertIsNone(result)
        
        # Test avec données plist incomplètes
        mock_plist_data_incomplete = {
            "Label": "com.test.agent"
            # Pas de ProgramArguments ni Program
        }
        
        with patch('builtins.open', mock_open()):
            with patch('plistlib.load') as mock_plist_load:
                mock_plist_load.return_value = mock_plist_data_incomplete
                
                result = collector._parse_plist("/test/incomplete.plist", "Global Agent")
                self.assertIsNone(result)
        
        # Test de la méthode collect avec mock des chemins
        with patch('os.path.isdir') as mock_isdir:
            mock_isdir.return_value = True
            
            with patch('os.listdir') as mock_listdir:
                mock_listdir.return_value = ['com.test.agent.plist']
                
                with patch.object(collector, '_parse_plist') as mock_parse:
                    mock_parse.return_value = persistence_entry
                    
                    entries = list(collector.collect())
                    self.assertEqual(len(entries), 1)
                    self.assertEqual(entries[0].label, "com.test.agent")

if __name__ == '__main__':
    unittest.main() 