import os
import winreg
import logging
from typing import List, Dict, Any
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)

class FilesCollector:
    """Collecte les informations sur les fichiers Windows."""
    
    def __init__(self):
        self.sensitive_paths = [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Windows\\Temp',
            'C:\\Users\\Administrator',
            'C:\\ProgramData'
        ]
        
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.jar'
        ]
    
    def collect(self, path: str = None, recursive: bool = True) -> List[Dict[str, Any]]:
        """Collecte les informations sur les fichiers."""
        if path is None:
            # Collecter depuis les chemins sensibles par défaut
            results = []
            for sensitive_path in self.sensitive_paths:
                if os.path.exists(sensitive_path):
                    path_results = self._collect_from_path(sensitive_path, recursive)
                    results.extend(path_results)
            return results
        else:
            return self._collect_from_path(path, recursive)
    
    def _collect_from_path(self, path: str, recursive: bool) -> List[Dict[str, Any]]:
        """Collecte les fichiers depuis un chemin spécifique."""
        results = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_info = self._get_file_info(file_path)
                        if file_info:
                            results.append(file_info)
            else:
                if os.path.isfile(path):
                    file_info = self._get_file_info(path)
                    if file_info:
                        results.append(file_info)
                elif os.path.isdir(path):
                    for item in os.listdir(path):
                        item_path = os.path.join(path, item)
                        if os.path.isfile(item_path):
                            file_info = self._get_file_info(item_path)
                            if file_info:
                                results.append(file_info)
        
        except PermissionError:
            logger.warning(f"Permission denied accessing {path}")
        except Exception as e:
            logger.error(f"Error collecting from {path}: {e}")
        
        return results
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Récupère les informations détaillées d'un fichier."""
        try:
            stat = os.stat(file_path)
            
            # Calculer le hash MD5
            file_hash = self._calculate_file_hash(file_path)
            
            # Vérifier si le fichier est suspect
            is_suspicious = self._is_suspicious_file(file_path)
            
            return {
                'type': 'windows_file',
                'path': file_path,
                'name': os.path.basename(file_path),
                'size_bytes': stat.st_size,
                'size_mb': round(stat.st_size / 1024 / 1024, 2),
                'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'extension': os.path.splitext(file_path)[1].lower(),
                'md5_hash': file_hash,
                'is_suspicious': is_suspicious,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcule le hash MD5 d'un fichier."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Détermine si un fichier est suspect."""
        # Vérifier l'extension
        extension = os.path.splitext(file_path)[1].lower()
        if extension in self.suspicious_extensions:
            return True
        
        # Vérifier le nom du fichier
        filename = os.path.basename(file_path).lower()
        suspicious_names = [
            'malware', 'virus', 'trojan', 'backdoor', 'keylogger',
            'suspicious', 'unknown', 'temp', 'tmp'
        ]
        
        if any(name in filename for name in suspicious_names):
            return True
        
        return False
    
    def get_suspicious_files(self, path: str = None) -> List[Dict[str, Any]]:
        """Récupère seulement les fichiers suspects."""
        all_files = self.collect(path)
        return [file for file in all_files if file.get('is_suspicious', False)]
    
    def get_files_by_extension(self, extension: str, path: str = None) -> List[Dict[str, Any]]:
        """Récupère les fichiers par extension."""
        all_files = self.collect(path)
        return [file for file in all_files if file.get('extension', '').lower() == extension.lower()]
    
    def get_large_files(self, min_size_mb: float = 100, path: str = None) -> List[Dict[str, Any]]:
        """Récupère les fichiers de grande taille."""
        all_files = self.collect(path)
        return [file for file in all_files if file.get('size_mb', 0) >= min_size_mb]
    
    def get_recent_files(self, hours: int = 24, path: str = None) -> List[Dict[str, Any]]:
        """Récupère les fichiers modifiés récemment."""
        all_files = self.collect(path)
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        
        recent_files = []
        for file in all_files:
            try:
                modified_time = datetime.fromisoformat(file['modified_time']).timestamp()
                if modified_time >= cutoff_time:
                    recent_files.append(file)
            except:
                continue
        
        return recent_files
    
    def delete_file(self, file_path: str) -> bool:
        """Tente de supprimer un fichier."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Successfully deleted file {file_path}")
                return True
            else:
                logger.warning(f"File {file_path} not found")
                return False
        except PermissionError:
            logger.error(f"Permission denied deleting {file_path}")
            return False
        except Exception as e:
            logger.error(f"Error deleting {file_path}: {e}")
            return False 