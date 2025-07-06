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
        return super().collect()

    def _collect(self) -> Dict[str, Any]:
        results = {
            'system_info': self.get_system_info(),
            'registry_keys': {},
            'suspicious_keys': [],
            'summary': {}
        }
        
        try:
            # Collecter les clés importantes
            results['registry_keys'] = self._get_important_keys()
            
            # Analyser les clés suspectes
            all_keys = []
            for category, keys in results['registry_keys'].items():
                if isinstance(keys, list):
                    all_keys.extend(keys)
            
            results['suspicious_keys'] = self._analyze_suspicious_keys(all_keys)
            
            # Générer un résumé
            total_keys = sum(len(keys) for keys in results['registry_keys'].values() if isinstance(keys, list))
            
            results['summary'] = {
                'total_categories': len(results['registry_keys']),
                'total_keys_scanned': total_keys,
                'suspicious_keys_count': len(results['suspicious_keys']),
                'categories': list(results['registry_keys'].keys()),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte du registre: {e}")
            results['error'] = str(e)
        
        return results
    
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
    
    def _analyze_suspicious_keys(self, keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les clés de registre pour détecter les clés suspectes"""
        suspicious_keys = []
        
        for key_info in keys:
            suspicious_flags = []
            
            # Vérifier les noms de clés suspects
            key_path = key_info.get('path', '').lower()
            suspicious_patterns = [
                'malware', 'virus', 'trojan', 'backdoor', 'keylogger', 'spyware',
                'persistence', 'autorun', 'startup', 'shell', 'winlogon'
            ]
            if any(pattern in key_path for pattern in suspicious_patterns):
                suspicious_flags.append("Nom de clé suspect")
            
            # Vérifier les valeurs suspectes
            values = key_info.get('values', [])
            for value in values:
                value_name = value.get('name', '').lower()
                value_data = str(value.get('value', '')).lower()
                
                # Vérifier les noms de valeurs suspects
                suspicious_value_names = ['malware', 'virus', 'trojan', 'backdoor', 'keylogger']
                if any(name in value_name for name in suspicious_value_names):
                    suspicious_flags.append("Nom de valeur suspect")
                
                # Vérifier les données suspectes
                suspicious_data_patterns = [
                    'cmd.exe', 'powershell', 'wscript', 'cscript', 'rundll32',
                    'regsvr32', 'mshta', 'certutil', 'bitsadmin'
                ]
                if any(pattern in value_data for pattern in suspicious_data_patterns):
                    suspicious_flags.append("Données suspectes")
                
                # Vérifier les chemins suspects
                if '\\temp\\' in value_data or '\\tmp\\' in value_data:
                    suspicious_flags.append("Chemin temporaire")
                
                # Vérifier les URLs suspectes
                if 'http://' in value_data or 'https://' in value_data:
                    suspicious_flags.append("URL suspecte")
            
            # Vérifier les sous-clés suspectes
            subkeys = key_info.get('subkeys', [])
            for subkey in subkeys:
                subkey_name = subkey.get('name', '').lower()
                if any(pattern in subkey_name for pattern in suspicious_patterns):
                    suspicious_flags.append("Sous-clé suspecte")
            
            # Si des flags suspects sont détectés, ajouter la clé à la liste
            if suspicious_flags:
                suspicious_key = key_info.copy()
                suspicious_key['suspicious_flags'] = suspicious_flags
                suspicious_key['risk_level'] = self._calculate_registry_risk_level(suspicious_flags)
                suspicious_keys.append(suspicious_key)
        
        return suspicious_keys
    
    def _calculate_registry_risk_level(self, suspicious_flags: List[str]) -> str:
        """Calcule le niveau de risque basé sur les flags suspects"""
        high_risk_flags = [
            "Nom de clé suspect",
            "Données suspectes"
        ]
        
        medium_risk_flags = [
            "Nom de valeur suspect",
            "Chemin temporaire",
            "Sous-clé suspecte"
        ]
        
        high_count = sum(1 for flag in suspicious_flags if flag in high_risk_flags)
        medium_count = sum(1 for flag in suspicious_flags if flag in medium_risk_flags)
        
        if high_count > 0:
            return "HIGH"
        elif medium_count > 1 or len(suspicious_flags) > 2:
            return "MEDIUM"
        else:
            return "LOW" 