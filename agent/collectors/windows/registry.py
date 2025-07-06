import winreg
import logging
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class RegistryCollector:
    """Collecte les informations du registre Windows."""
    
    def __init__(self):
        self.suspicious_keys = [
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDORSYS',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDORSYS'
        ]
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les informations du registre."""
        results = []
        
        # Collecter les clés de démarrage
        startup_results = self._collect_startup_keys()
        results.extend(startup_results)
        
        # Collecter les clés de persistance
        persistence_results = self._collect_persistence_keys()
        results.extend(persistence_results)
        
        # Collecter les clés de configuration système
        config_results = self._collect_system_config_keys()
        results.extend(config_results)
        
        return results
    
    def _collect_startup_keys(self) -> List[Dict[str, Any]]:
        """Collecte les clés de démarrage automatique."""
        results = []
        
        startup_keys = [
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx')
        ]
        
        for hkey, subkey in startup_keys:
            try:
                key_results = self._collect_registry_key(hkey, subkey, 'startup')
                results.extend(key_results)
            except Exception as e:
                logger.error(f"Error collecting startup key {subkey}: {e}")
        
        return results
    
    def _collect_persistence_keys(self) -> List[Dict[str, Any]]:
        """Collecte les clés de persistance."""
        results = []
        
        persistence_keys = [
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
        ]
        
        for hkey, subkey in persistence_keys:
            try:
                key_results = self._collect_registry_key(hkey, subkey, 'persistence')
                results.extend(key_results)
            except Exception as e:
                logger.error(f"Error collecting persistence key {subkey}: {e}")
        
        return results
    
    def _collect_system_config_keys(self) -> List[Dict[str, Any]]:
        """Collecte les clés de configuration système."""
        results = []
        
        config_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')
        ]
        
        for hkey, subkey in config_keys:
            try:
                key_results = self._collect_registry_key(hkey, subkey, 'system_config')
                results.extend(key_results)
            except Exception as e:
                logger.error(f"Error collecting config key {subkey}: {e}")
        
        return results
    
    def _collect_registry_key(self, hkey, subkey: str, key_type: str) -> List[Dict[str, Any]]:
        """Collecte les valeurs d'une clé de registre."""
        results = []
        
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, i)
                        
                        # Vérifier si la valeur est suspecte
                        is_suspicious = self._is_suspicious_value(name, value)
                        
                        result = {
                            'type': 'windows_registry',
                            'key_type': key_type,
                            'hive': self._get_hive_name(hkey),
                            'subkey': subkey,
                            'value_name': name,
                            'value_data': str(value),
                            'value_type': self._get_value_type_name(value_type),
                            'is_suspicious': is_suspicious,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        results.append(result)
                        i += 1
                    
                    except WindowsError:
                        break
        
        except Exception as e:
            logger.error(f"Error reading registry key {subkey}: {e}")
        
        return results
    
    def _get_hive_name(self, hkey) -> str:
        """Retourne le nom de la ruche de registre."""
        if hkey == winreg.HKEY_CURRENT_USER:
            return 'HKEY_CURRENT_USER'
        elif hkey == winreg.HKEY_LOCAL_MACHINE:
            return 'HKEY_LOCAL_MACHINE'
        elif hkey == winreg.HKEY_CLASSES_ROOT:
            return 'HKEY_CLASSES_ROOT'
        elif hkey == winreg.HKEY_USERS:
            return 'HKEY_USERS'
        else:
            return 'UNKNOWN'
    
    def _get_value_type_name(self, value_type: int) -> str:
        """Retourne le nom du type de valeur."""
        type_names = {
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
        return type_names.get(value_type, f'UNKNOWN_{value_type}')
    
    def _is_suspicious_value(self, name: str, value: Any) -> bool:
        """Détermine si une valeur de registre est suspecte."""
        suspicious_indicators = [
            'malware', 'virus', 'trojan', 'backdoor', 'keylogger',
            'suspicious', 'unknown', 'temp', 'tmp', 'cmd', 'powershell'
        ]
        
        name_lower = name.lower()
        value_str = str(value).lower()
        
        # Vérifier le nom de la valeur
        if any(indicator in name_lower for indicator in suspicious_indicators):
            return True
        
        # Vérifier les données de la valeur
        if any(indicator in value_str for indicator in suspicious_indicators):
            return True
        
        return False
    
    def get_suspicious_registry_entries(self) -> List[Dict[str, Any]]:
        """Récupère seulement les entrées de registre suspectes."""
        all_entries = self.collect()
        return [entry for entry in all_entries if entry.get('is_suspicious', False)]
    
    def get_startup_entries(self) -> List[Dict[str, Any]]:
        """Récupère les entrées de démarrage automatique."""
        all_entries = self.collect()
        return [entry for entry in all_entries if entry.get('key_type') == 'startup']
    
    def get_persistence_entries(self) -> List[Dict[str, Any]]:
        """Récupère les entrées de persistance."""
        all_entries = self.collect()
        return [entry for entry in all_entries if entry.get('key_type') == 'persistence']
    
    def delete_registry_value(self, hive_name: str, subkey: str, value_name: str) -> bool:
        """Tente de supprimer une valeur de registre."""
        try:
            hkey = self._get_hkey_from_name(hive_name)
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, value_name)
                logger.info(f"Successfully deleted registry value {hive_name}\\{subkey}\\{value_name}")
                return True
        
        except Exception as e:
            logger.error(f"Error deleting registry value {hive_name}\\{subkey}\\{value_name}: {e}")
            return False
    
    def _get_hkey_from_name(self, hive_name: str):
        """Retourne la constante HKEY à partir du nom."""
        hive_map = {
            'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
            'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
            'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
            'HKEY_USERS': winreg.HKEY_USERS
        }
        return hive_map.get(hive_name, winreg.HKEY_CURRENT_USER) 