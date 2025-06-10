from typing import Dict, List, Any, Optional
from datetime import datetime
import winreg
import win32api
import win32security
import win32con
import win32ts
import win32net
import win32netcon
import win32profile
import win32cred
import win32security
import win32file
import win32timezone
import win32evtlog
import win32evtlogutil
import win32gui
import win32ui
import win32print
import win32com.client
import pythoncom
import yara
import hashlib
import os
from pathlib import Path
from .base import WindowsCollector

class WindowsRegistryCollector(WindowsCollector):
    """Collecteur pour les registres Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
        
        # Clés de registre importantes à surveiller
        self.important_keys = {
            'run': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
            ],
            'services': [
                r'SYSTEM\CurrentControlSet\Services'
            ],
            'startup': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
            ],
            'policies': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
                r'SOFTWARE\Policies\Microsoft\Windows',
                r'SOFTWARE\Policies\Microsoft\Windows\System',
                r'SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ],
            'explorer': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            ],
            'programs': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Management',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Host'
            ],
            'security': [
                r'SYSTEM\CurrentControlSet\Control\Lsa',
                r'SYSTEM\CurrentControlSet\Control\SecurityProviders',
                r'SYSTEM\CurrentControlSet\Services\NTDS',
                r'SYSTEM\CurrentControlSet\Services\Netlogon'
            ],
            'network': [
                r'SYSTEM\CurrentControlSet\Services\Tcpip',
                r'SYSTEM\CurrentControlSet\Services\Tcpip6',
                r'SYSTEM\CurrentControlSet\Services\NetBT',
                r'SYSTEM\CurrentControlSet\Services\LanmanServer',
                r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation'
            ],
            'drivers': [
                r'SYSTEM\CurrentControlSet\Control\Class',
                r'SYSTEM\CurrentControlSet\Enum',
                r'SYSTEM\CurrentControlSet\Services'
            ],
            'system': [
                r'SYSTEM\CurrentControlSet\Control',
                r'SYSTEM\CurrentControlSet\Services',
                r'SYSTEM\CurrentControlSet\Hardware Profiles',
                r'SYSTEM\CurrentControlSet\Enum'
            ]
        }
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les registres"""
        if not self._check_privileges():
            return {'error': 'Privilèges insuffisants'}
        
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'hives': {
                    'HKEY_CLASSES_ROOT': self._get_hive_data(winreg.HKEY_CLASSES_ROOT),
                    'HKEY_CURRENT_USER': self._get_hive_data(winreg.HKEY_CURRENT_USER),
                    'HKEY_LOCAL_MACHINE': self._get_hive_data(winreg.HKEY_LOCAL_MACHINE),
                    'HKEY_USERS': self._get_hive_data(winreg.HKEY_USERS),
                    'HKEY_CURRENT_CONFIG': self._get_hive_data(winreg.HKEY_CURRENT_CONFIG)
                },
                'important_keys': self._get_important_keys()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des registres: {e}")
            return {'error': str(e)}
    
    def _get_hive_data(self, hive: int) -> Dict[str, Any]:
        """Récupère les données d'une ruche"""
        try:
            # Récupération des sous-clés
            subkeys = self._get_subkeys(hive)
            
            # Récupération des valeurs
            values = self._get_values(hive)
            
            return {
                'subkeys': subkeys,
                'values': values
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des données de la ruche: {e}")
            return {}
    
    def _get_subkeys(self, key: int) -> List[Dict[str, Any]]:
        """Récupère les sous-clés d'une clé"""
        subkeys = []
        
        try:
            # Récupération du nombre de sous-clés
            num_subkeys = winreg.QueryInfoKey(key)[0]
            
            # Récupération des sous-clés
            for i in range(num_subkeys):
                try:
                    # Récupération du nom de la sous-clé
                    subkey_name = winreg.EnumKey(key, i)
                    
                    # Ouverture de la sous-clé
                    subkey = winreg.OpenKey(key, subkey_name)
                    
                    # Récupération des informations de la sous-clé
                    subkey_info = {
                        'name': subkey_name,
                        'subkeys': self._get_subkeys(subkey),
                        'values': self._get_values(subkey)
                    }
                    
                    # Fermeture de la sous-clé
                    winreg.CloseKey(subkey)
                    
                    subkeys.append(subkey_info)
                    
                except:
                    continue
            
            return subkeys
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des sous-clés: {e}")
            return []
    
    def _get_values(self, key: int) -> List[Dict[str, Any]]:
        """Récupère les valeurs d'une clé"""
        values = []
        
        try:
            # Récupération du nombre de valeurs
            num_values = winreg.QueryInfoKey(key)[1]
            
            # Récupération des valeurs
            for i in range(num_values):
                try:
                    # Récupération du nom et de la valeur
                    name, value, type = winreg.EnumValue(key, i)
                    
                    # Formatage de la valeur
                    formatted_value = self._format_value(value, type)
                    
                    values.append({
                        'name': name,
                        'value': formatted_value,
                        'type': self._get_value_type(type)
                    })
                    
                except:
                    continue
            
            return values
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des valeurs: {e}")
            return []
    
    def _get_important_keys(self) -> Dict[str, List[Dict[str, Any]]]:
        """Récupère les clés importantes"""
        important_keys = {}
        
        for category, keys in self.important_keys.items():
            important_keys[category] = []
            
            for key_path in keys:
                try:
                    # Ouverture de la clé
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    
                    # Récupération des informations de la clé
                    key_info = {
                        'path': key_path,
                        'subkeys': self._get_subkeys(key),
                        'values': self._get_values(key)
                    }
                    
                    # Fermeture de la clé
                    winreg.CloseKey(key)
                    
                    important_keys[category].append(key_info)
                    
                except:
                    continue
        
        return important_keys
    
    def _format_value(self, value: Any, type: int) -> Any:
        """Formate une valeur de registre"""
        try:
            if type == winreg.REG_BINARY:
                return [hex(b) for b in value]
            elif type == winreg.REG_MULTI_SZ:
                return list(value)
            elif type == winreg.REG_DWORD:
                return value
            elif type == winreg.REG_QWORD:
                return value
            elif type == winreg.REG_SZ:
                return value
            elif type == winreg.REG_EXPAND_SZ:
                return value
            else:
                return str(value)
        except:
            return str(value)
    
    def _get_value_type(self, type: int) -> str:
        """Convertit le type de valeur en chaîne de caractères"""
        types = {
            winreg.REG_BINARY: 'REG_BINARY',
            winreg.REG_DWORD: 'REG_DWORD',
            winreg.REG_DWORD_LITTLE_ENDIAN: 'REG_DWORD_LITTLE_ENDIAN',
            winreg.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
            winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
            winreg.REG_LINK: 'REG_LINK',
            winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
            winreg.REG_NONE: 'REG_NONE',
            winreg.REG_QWORD: 'REG_QWORD',
            winreg.REG_QWORD_LITTLE_ENDIAN: 'REG_QWORD_LITTLE_ENDIAN',
            winreg.REG_SZ: 'REG_SZ'
        }
        return types.get(type, 'UNKNOWN')
    
    def get_key_value(self, key_path: str, value_name: str) -> Optional[Any]:
        """Récupère la valeur d'une clé"""
        try:
            # Ouverture de la clé
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            # Récupération de la valeur
            value, type = winreg.QueryValueEx(key, value_name)
            
            # Formatage de la valeur
            formatted_value = self._format_value(value, type)
            
            # Fermeture de la clé
            winreg.CloseKey(key)
            
            return formatted_value
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de la valeur {value_name} de la clé {key_path}: {e}")
            return None
    
    def set_key_value(self, key_path: str, value_name: str, value: Any, type: int) -> bool:
        """Définit la valeur d'une clé"""
        try:
            # Ouverture de la clé
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            
            # Définition de la valeur
            winreg.SetValueEx(key, value_name, 0, type, value)
            
            # Fermeture de la clé
            winreg.CloseKey(key)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la définition de la valeur {value_name} de la clé {key_path}: {e}")
            return False
    
    def delete_key_value(self, key_path: str, value_name: str) -> bool:
        """Supprime la valeur d'une clé"""
        try:
            # Ouverture de la clé
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            
            # Suppression de la valeur
            winreg.DeleteValue(key, value_name)
            
            # Fermeture de la clé
            winreg.CloseKey(key)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la suppression de la valeur {value_name} de la clé {key_path}: {e}")
            return False
    
    def create_key(self, key_path: str) -> bool:
        """Crée une clé"""
        try:
            # Création de la clé
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la création de la clé {key_path}: {e}")
            return False
    
    def delete_key(self, key_path: str) -> bool:
        """Supprime une clé"""
        try:
            # Suppression de la clé
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la suppression de la clé {key_path}: {e}")
            return False 