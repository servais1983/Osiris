from typing import Dict, List, Any, Optional
from datetime import datetime
import os
import win32file
import win32security
import win32api
import win32con
import win32ts
import win32net
import win32netcon
import win32profile
import win32cred
import win32security
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
import json
import shutil
from pathlib import Path
from .base import WindowsCollector

class WindowsFileCollector(WindowsCollector):
    """Collecteur pour les fichiers Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
        
        # Chemins importants à surveiller
        self.important_paths = {
            'system32': 'C:\\Windows\\System32',
            'program_files': 'C:\\Program Files',
            'program_files_x86': 'C:\\Program Files (x86)',
            'appdata': os.path.expanduser('~\\AppData'),
            'startup': os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            'recent': os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Windows\\Recent'),
            'prefetch': 'C:\\Windows\\Prefetch',
            'temp': os.environ.get('TEMP'),
            'downloads': os.path.expanduser('~\\Downloads'),
            'documents': os.path.expanduser('~\\Documents')
        }
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les fichiers"""
        if not self._check_privileges():
            return {'error': 'Privilèges insuffisants'}
        
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'important_paths': self._scan_important_paths(),
                'recent_files': self._get_recent_files(),
                'startup_files': self._get_startup_files(),
                'prefetch_files': self._get_prefetch_files(),
                'temp_files': self._get_temp_files(),
                'downloads': self._get_downloads(),
                'documents': self._get_documents()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des fichiers: {e}")
            return {'error': str(e)}
    
    def _scan_important_paths(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scanne les chemins importants"""
        results = {}
        
        for name, path in self.important_paths.items():
            if path and os.path.exists(path):
                try:
                    results[name] = self._scan_directory(path)
                except Exception as e:
                    self.logger.error(f"Erreur lors du scan du répertoire {path}: {e}")
                    results[name] = []
            else:
                results[name] = []
        
        return results
    
    def _scan_directory(self, path: str, max_depth: int = 2) -> List[Dict[str, Any]]:
        """Scanne un répertoire récursivement"""
        files = []
        
        try:
            for root, dirs, filenames in os.walk(path):
                # Calcul de la profondeur
                depth = root[len(path):].count(os.sep)
                if depth > max_depth:
                    continue
                
                for filename in filenames:
                    try:
                        file_path = os.path.join(root, filename)
                        file_info = self._get_file_info(file_path)
                        if file_info:
                            files.append(file_info)
                    except:
                        continue
        except:
            pass
        
        return files
    
    def _get_file_info(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un fichier"""
        try:
            # Vérification de l'existence
            if not os.path.exists(file_path):
                return None
            
            # Informations de base
            stat = os.stat(file_path)
            
            # Informations de sécurité
            security_info = self._get_file_security(file_path)
            
            # Calcul des hashes
            hashes = self._calculate_file_hashes(file_path)
            
            # Informations sur le type de fichier
            file_type = self._get_file_type(file_path)
            
            return {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'attributes': self._get_file_attributes(stat.st_file_attributes),
                'security': security_info,
                'hashes': hashes,
                'type': file_type
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du fichier {file_path}: {e}")
            return None
    
    def _get_file_security(self, file_path: str) -> Dict[str, Any]:
        """Récupère les informations de sécurité d'un fichier"""
        security_info = {}
        
        try:
            # Récupération du descripteur de sécurité
            sd = win32security.GetFileSecurity(
                file_path,
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.GROUP_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Propriétaire
            try:
                owner_sid = sd.GetSecurityDescriptorOwner()
                owner_name = win32security.LookupAccountSid(None, owner_sid)[0]
                security_info['owner'] = {
                    'sid': win32security.ConvertSidToStringSid(owner_sid),
                    'name': owner_name
                }
            except:
                security_info['owner'] = None
            
            # Groupe
            try:
                group_sid = sd.GetSecurityDescriptorGroup()
                group_name = win32security.LookupAccountSid(None, group_sid)[0]
                security_info['group'] = {
                    'sid': win32security.ConvertSidToStringSid(group_sid),
                    'name': group_name
                }
            except:
                security_info['group'] = None
            
            # ACL
            try:
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl:
                    aces = []
                    for i in range(dacl.GetAceCount()):
                        ace_type, ace_flags, ace_mask, ace_sid = dacl.GetAce(i)
                        try:
                            ace_name = win32security.LookupAccountSid(None, ace_sid)[0]
                            aces.append({
                                'type': self._get_ace_type(ace_type),
                                'flags': self._get_ace_flags(ace_flags),
                                'mask': self._get_ace_mask(ace_mask),
                                'sid': win32security.ConvertSidToStringSid(ace_sid),
                                'name': ace_name
                            })
                        except:
                            continue
                    security_info['acl'] = aces
                else:
                    security_info['acl'] = []
            except:
                security_info['acl'] = []
            
            return security_info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de sécurité du fichier {file_path}: {e}")
            return {}
    
    def _get_file_attributes(self, attributes: int) -> List[str]:
        """Convertit les attributs de fichier en liste de chaînes"""
        attr_list = []
        
        if attributes & win32con.FILE_ATTRIBUTE_ARCHIVE:
            attr_list.append('ARCHIVE')
        if attributes & win32con.FILE_ATTRIBUTE_HIDDEN:
            attr_list.append('HIDDEN')
        if attributes & win32con.FILE_ATTRIBUTE_NORMAL:
            attr_list.append('NORMAL')
        if attributes & win32con.FILE_ATTRIBUTE_OFFLINE:
            attr_list.append('OFFLINE')
        if attributes & win32con.FILE_ATTRIBUTE_READONLY:
            attr_list.append('READONLY')
        if attributes & win32con.FILE_ATTRIBUTE_SYSTEM:
            attr_list.append('SYSTEM')
        if attributes & win32con.FILE_ATTRIBUTE_TEMPORARY:
            attr_list.append('TEMPORARY')
        
        return attr_list
    
    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcule les hashes d'un fichier"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                # MD5
                hashes['md5'] = hashlib.md5(data).hexdigest()
                
                # SHA1
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                
                # SHA256
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
                
            return hashes
            
        except Exception as e:
            self.logger.error(f"Erreur lors du calcul des hashes du fichier {file_path}: {e}")
            return {}
    
    def _get_file_type(self, file_path: str) -> Dict[str, Any]:
        """Récupère le type d'un fichier"""
        file_type = {}
        
        try:
            # Extension
            file_type['extension'] = os.path.splitext(file_path)[1].lower()
            
            # Type MIME
            try:
                import mimetypes
                mime_type, _ = mimetypes.guess_type(file_path)
                file_type['mime_type'] = mime_type
            except:
                file_type['mime_type'] = None
            
            # Signature de fichier
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    file_type['signature'] = header.hex()
            except:
                file_type['signature'] = None
            
            return file_type
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération du type du fichier {file_path}: {e}")
            return {}
    
    def _get_recent_files(self) -> List[Dict[str, Any]]:
        """Récupère les fichiers récents"""
        recent_files = []
        
        try:
            recent_path = self.important_paths['recent']
            if os.path.exists(recent_path):
                for file_path in os.listdir(recent_path):
                    try:
                        full_path = os.path.join(recent_path, file_path)
                        file_info = self._get_file_info(full_path)
                        if file_info:
                            recent_files.append(file_info)
                    except:
                        continue
            
            return recent_files
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des fichiers récents: {e}")
            return []
    
    def _get_startup_files(self) -> List[Dict[str, Any]]:
        """Récupère les fichiers de démarrage"""
        startup_files = []
        
        try:
            startup_path = self.important_paths['startup']
            if os.path.exists(startup_path):
                for file_path in os.listdir(startup_path):
                    try:
                        full_path = os.path.join(startup_path, file_path)
                        file_info = self._get_file_info(full_path)
                        if file_info:
                            startup_files.append(file_info)
                    except:
                        continue
            
            return startup_files
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des fichiers de démarrage: {e}")
            return []
    
    def _get_prefetch_files(self) -> List[Dict[str, Any]]:
        """Récupère les fichiers Prefetch"""
        prefetch_files = []
        
        try:
            prefetch_path = self.important_paths['prefetch']
            if os.path.exists(prefetch_path):
                for file_path in os.listdir(prefetch_path):
                    try:
                        full_path = os.path.join(prefetch_path, file_path)
                        file_info = self._get_file_info(full_path)
                        if file_info:
                            prefetch_files.append(file_info)
                    except:
                        continue
            
            return prefetch_files
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des fichiers Prefetch: {e}")
            return []
    
    def _get_temp_files(self) -> List[Dict[str, Any]]:
        """Récupère les fichiers temporaires"""
        temp_files = []
        
        try:
            temp_path = self.important_paths['temp']
            if os.path.exists(temp_path):
                for file_path in os.listdir(temp_path):
                    try:
                        full_path = os.path.join(temp_path, file_path)
                        file_info = self._get_file_info(full_path)
                        if file_info:
                            temp_files.append(file_info)
                    except:
                        continue
            
            return temp_files
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des fichiers temporaires: {e}")
            return []
    
    def _get_downloads(self) -> List[Dict[str, Any]]:
        """Récupère les fichiers téléchargés"""
        downloads = []
        
        try:
            downloads_path = self.important_paths['downloads']
            if os.path.exists(downloads_path):
                for file_path in os.listdir(downloads_path):
                    try:
                        full_path = os.path.join(downloads_path, file_path)
                        file_info = self._get_file_info(full_path)
                        if file_info:
                            downloads.append(file_info)
                    except:
                        continue
            
            return downloads
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des fichiers téléchargés: {e}")
            return []
    
    def _get_documents(self) -> List[Dict[str, Any]]:
        """Récupère les documents"""
        documents = []
        
        try:
            documents_path = self.important_paths['documents']
            if os.path.exists(documents_path):
                for file_path in os.listdir(documents_path):
                    try:
                        full_path = os.path.join(documents_path, file_path)
                        file_info = self._get_file_info(full_path)
                        if file_info:
                            documents.append(file_info)
                    except:
                        continue
            
            return documents
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des documents: {e}")
            return []
    
    def _get_ace_type(self, ace_type: int) -> str:
        """Convertit le type d'ACE en chaîne de caractères"""
        types = {
            0: 'ACCESS_ALLOWED',
            1: 'ACCESS_DENIED',
            2: 'SYSTEM_AUDIT',
            3: 'SYSTEM_ALARM'
        }
        return types.get(ace_type, 'UNKNOWN')
    
    def _get_ace_flags(self, ace_flags: int) -> List[str]:
        """Convertit les drapeaux d'ACE en liste de chaînes"""
        flags = []
        
        if ace_flags & win32security.OBJECT_INHERIT_ACE:
            flags.append('OBJECT_INHERIT')
        if ace_flags & win32security.CONTAINER_INHERIT_ACE:
            flags.append('CONTAINER_INHERIT')
        if ace_flags & win32security.NO_PROPAGATE_INHERIT_ACE:
            flags.append('NO_PROPAGATE_INHERIT')
        if ace_flags & win32security.INHERIT_ONLY_ACE:
            flags.append('INHERIT_ONLY')
        if ace_flags & win32security.SUCCESSFUL_ACCESS_ACE_FLAG:
            flags.append('SUCCESSFUL_ACCESS')
        if ace_flags & win32security.FAILED_ACCESS_ACE_FLAG:
            flags.append('FAILED_ACCESS')
        
        return flags
    
    def _get_ace_mask(self, ace_mask: int) -> List[str]:
        """Convertit le masque d'ACE en liste de chaînes"""
        masks = []
        
        if ace_mask & win32con.GENERIC_READ:
            masks.append('GENERIC_READ')
        if ace_mask & win32con.GENERIC_WRITE:
            masks.append('GENERIC_WRITE')
        if ace_mask & win32con.GENERIC_EXECUTE:
            masks.append('GENERIC_EXECUTE')
        if ace_mask & win32con.GENERIC_ALL:
            masks.append('GENERIC_ALL')
        if ace_mask & win32con.FILE_READ_DATA:
            masks.append('FILE_READ_DATA')
        if ace_mask & win32con.FILE_WRITE_DATA:
            masks.append('FILE_WRITE_DATA')
        if ace_mask & win32con.FILE_APPEND_DATA:
            masks.append('FILE_APPEND_DATA')
        if ace_mask & win32con.FILE_READ_EA:
            masks.append('FILE_READ_EA')
        if ace_mask & win32con.FILE_WRITE_EA:
            masks.append('FILE_WRITE_EA')
        if ace_mask & win32con.FILE_EXECUTE:
            masks.append('FILE_EXECUTE')
        if ace_mask & win32con.FILE_DELETE_CHILD:
            masks.append('FILE_DELETE_CHILD')
        if ace_mask & win32con.FILE_READ_ATTRIBUTES:
            masks.append('FILE_READ_ATTRIBUTES')
        if ace_mask & win32con.FILE_WRITE_ATTRIBUTES:
            masks.append('FILE_WRITE_ATTRIBUTES')
        
        return masks 