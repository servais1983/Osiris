"""
Tests pour le module validation Windows.
"""

import unittest
from unittest.mock import patch
from collectors.windows.validation import (
    ValidationError,
    validate_path,
    validate_file_path,
    validate_dir_path,
    validate_pid,
    validate_port,
    validate_ip,
    validate_mac,
    validate_registry_key,
    validate_service_name,
    validate_username,
    validate_event_id,
    validate_timestamp,
    validate_data
)

class TestWindowsValidation(unittest.TestCase):
    """Tests pour la validation des données Windows."""
    
    def test_validate_path_valid(self):
        with patch('os.path.exists', return_value=True):
            self.assertEqual(validate_path('/test/path'), '/test/path')
    def test_validate_path_empty(self):
        with self.assertRaises(ValidationError):
            validate_path('')
    def test_validate_path_nonexistent(self):
        with patch('os.path.exists', return_value=False):
            with self.assertRaises(ValidationError):
                validate_path('/nonexistent/path')
    def test_validate_pid_valid(self):
        self.assertEqual(validate_pid(1234), 1234)
    def test_validate_pid_negative(self):
        with self.assertRaises(ValidationError):
            validate_pid(-1)
    def test_validate_port_valid(self):
        self.assertEqual(validate_port(80), 80)
    def test_validate_port_invalid(self):
        with self.assertRaises(ValidationError):
            validate_port(70000)
    def test_validate_ip_valid(self):
        self.assertEqual(validate_ip('127.0.0.1'), '127.0.0.1')
    def test_validate_ip_invalid(self):
        with self.assertRaises(ValidationError):
            validate_ip('999.0.0.1')
    def test_validate_mac_valid(self):
        self.assertEqual(validate_mac('00:11:22:33:44:55'), '00:11:22:33:44:55')
    def test_validate_mac_invalid(self):
        with self.assertRaises(ValidationError):
            validate_mac('invalid-mac')
    def test_validate_registry_key_valid(self):
        self.assertEqual(validate_registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Test'), 'HKEY_LOCAL_MACHINE\SOFTWARE\Test')
    def test_validate_registry_key_invalid(self):
        with self.assertRaises(ValidationError):
            validate_registry_key('invalid key!')
    def test_validate_service_name_valid(self):
        self.assertEqual(validate_service_name('MyService'), 'MyService')
    def test_validate_service_name_invalid(self):
        with self.assertRaises(ValidationError):
            validate_service_name('')
    def test_validate_username_valid(self):
        self.assertEqual(validate_username('user'), 'user')
    def test_validate_username_invalid(self):
        with self.assertRaises(ValidationError):
            validate_username('')
    def test_validate_event_id_valid(self):
        self.assertEqual(validate_event_id(4624), 4624)
    def test_validate_event_id_invalid(self):
        with self.assertRaises(ValidationError):
            validate_event_id(-1)
    def test_validate_timestamp_valid(self):
        self.assertIsNotNone(validate_timestamp('2021-01-01T12:00:00'))
    def test_validate_timestamp_invalid(self):
        with self.assertRaises(ValidationError):
            validate_timestamp('invalid-date')
    def test_validate_data_empty(self):
        """Test de validation de données vides avec timestamp."""
        # Fournir un timestamp comme attendu par la fonction
        data_with_timestamp = {'timestamp': '2021-01-01T12:00:00'}
        self.assertEqual(validate_data(data_with_timestamp), data_with_timestamp)

if __name__ == '__main__':
    unittest.main() 