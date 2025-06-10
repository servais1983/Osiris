"""
Tests d'intégration pour les collecteurs Windows.
"""

import unittest
import asyncio
from datetime import datetime
from typing import Dict, List, Any
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

class TestWindowsCollectorsIntegration(unittest.TestCase):
    """Tests d'intégration pour les collecteurs Windows."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        self.collectors = [
            BrowserHistoryCollector(),
            WindowsEventLogCollector(),
            WindowsEventCollector(),
            WindowsFileCollector(),
            WindowsNetworkCollector(),
            WindowsProcessCollector(),
            WindowsRegistryCollector(),
            WindowsServiceCollector(),
            WindowsUserCollector()
        ]
    
    def test_collectors_initialization(self):
        """Test l'initialisation des collecteurs."""
        for collector in self.collectors:
            self.assertIsInstance(collector, WindowsCollector)
            self.assertTrue(hasattr(collector, 'collect'))
    
    def test_collectors_privileges(self):
        """Test la vérification des privilèges."""
        for collector in self.collectors:
            if collector.requires_admin:
                self.assertTrue(collector._check_privileges())
    
    def test_collectors_data_format(self):
        """Test le format des données collectées."""
        for collector in self.collectors:
            data = collector.collect()
            self.assertIsInstance(data, dict)
            self.assertIn('timestamp', data)
            self.assertIsInstance(data['timestamp'], str)
    
    def test_collectors_error_handling(self):
        """Test la gestion des erreurs."""
        for collector in self.collectors:
            # Test avec un chemin invalide
            if isinstance(collector, WindowsFileCollector):
                data = collector._get_file_info('invalid/path')
                self.assertIsNone(data)
            
            # Test avec un PID invalide
            if isinstance(collector, WindowsProcessCollector):
                data = collector._get_process_info(-1)
                self.assertIsNone(data)
            
            # Test avec une clé de registre invalide
            if isinstance(collector, WindowsRegistryCollector):
                data = collector._get_registry_info('invalid/key')
                self.assertIsNone(data)
    
    def test_collectors_data_consistency(self):
        """Test la cohérence des données collectées."""
        for collector in self.collectors:
            data = collector.collect()
            
            # Vérification du timestamp
            timestamp = datetime.fromisoformat(data['timestamp'])
            self.assertLessEqual(timestamp, datetime.now())
            
            # Vérification des données spécifiques
            if isinstance(collector, BrowserHistoryCollector):
                self.assertIn('history', data)
                self.assertIsInstance(data['history'], list)
            
            elif isinstance(collector, WindowsEventLogCollector):
                self.assertIn('events', data)
                self.assertIsInstance(data['events'], list)
            
            elif isinstance(collector, WindowsFileCollector):
                self.assertIn('files', data)
                self.assertIsInstance(data['files'], list)
            
            elif isinstance(collector, WindowsNetworkCollector):
                self.assertIn('connections', data)
                self.assertIsInstance(data['connections'], list)
            
            elif isinstance(collector, WindowsProcessCollector):
                self.assertIn('processes', data)
                self.assertIsInstance(data['processes'], list)
            
            elif isinstance(collector, WindowsRegistryCollector):
                self.assertIn('keys', data)
                self.assertIsInstance(data['keys'], list)
            
            elif isinstance(collector, WindowsServiceCollector):
                self.assertIn('services', data)
                self.assertIsInstance(data['services'], list)
            
            elif isinstance(collector, WindowsUserCollector):
                self.assertIn('users', data)
                self.assertIsInstance(data['users'], list)
    
    def test_collectors_performance(self):
        """Test les performances des collecteurs."""
        for collector in self.collectors:
            start_time = datetime.now()
            data = collector.collect()
            end_time = datetime.now()
            
            # Vérification du temps d'exécution
            execution_time = (end_time - start_time).total_seconds()
            self.assertLess(execution_time, 30)  # Maximum 30 secondes par collecteur
    
    def test_collectors_memory_usage(self):
        """Test l'utilisation de la mémoire des collecteurs."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        for collector in self.collectors:
            data = collector.collect()
            current_memory = process.memory_info().rss
            
            # Vérification de l'utilisation de la mémoire
            memory_increase = current_memory - initial_memory
            self.assertLess(memory_increase, 100 * 1024 * 1024)  # Maximum 100 MB par collecteur
    
    def test_collectors_concurrent_execution(self):
        """Test l'exécution concurrente des collecteurs."""
        async def collect_data(collector: WindowsCollector) -> Dict[str, Any]:
            return collector.collect()
        
        async def run_collectors():
            tasks = [collect_data(collector) for collector in self.collectors]
            return await asyncio.gather(*tasks)
        
        results = asyncio.run(run_collectors())
        
        # Vérification des résultats
        self.assertEqual(len(results), len(self.collectors))
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertIn('timestamp', result)
    
    def test_collectors_data_validation(self):
        """Test la validation des données collectées."""
        for collector in self.collectors:
            data = collector.collect()
            
            # Vérification des types de données
            for key, value in data.items():
                if key == 'timestamp':
                    self.assertIsInstance(value, str)
                elif isinstance(value, list):
                    for item in value:
                        self.assertIsInstance(item, dict)
                elif isinstance(value, dict):
                    for k, v in value.items():
                        self.assertIsInstance(k, str)
                        self.assertIsInstance(v, (str, int, float, bool, list, dict, type(None)))

if __name__ == '__main__':
    unittest.main() 