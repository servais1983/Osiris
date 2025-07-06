from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import os
import sys
import win32security
import win32api
import win32con
import win32process
import win32event
import win32service
import win32serviceutil
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
import psutil
import yara
import hashlib
import json
import sqlite3
import winreg
import ctypes
from pathlib import Path

# Imports conditionnels pour la portabilité
try:
    import win32security
    import win32api
    import win32con
    import win32process
    import win32event
    import win32service
    import win32serviceutil
    import win32ts
    import win32net
    import win32netcon
    import win32profile
    import win32cred
    import win32file
    import win32timezone
    import win32evtlog
    import win32evtlogutil
    import win32gui
    import win32ui
    import win32print
    import win32com.client
    import pythoncom
    import winreg
except ImportError:
    win32security = win32api = win32con = win32process = win32event = None
    win32service = win32serviceutil = win32ts = win32net = win32netcon = None
    win32profile = win32cred = win32file = win32timezone = None
    win32evtlog = win32evtlogutil = win32gui = win32ui = win32print = None
    win32com = pythoncom = winreg = None

try:
    import psutil
except ImportError:
    psutil = None
try:
    import yara
except ImportError:
    yara = None

class WindowsCollector(ABC):
    """Classe de base pour les collecteurs Windows (multi-OS safe)"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.requires_admin = False
        self.requires_system = False
    
    def _windows_available(self):
        return all([
            win32api, win32security, win32con, ctypes
        ])
    
    def check_privileges(self) -> bool:
        """Vérifie les privilèges nécessaires"""
        if not self._windows_available():
            self.logger.warning("Fonctionnalité Windows non disponible sur cet OS.")
            return False
        try:
            if self.requires_admin:
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    self.logger.error("Privilèges administrateur requis")
                    return False
            if self.requires_system:
                priv_flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
                h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), priv_flags)
                priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_SYSTEM_ENVIRONMENT_NAME)
                win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification des privilèges: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Récupère les informations système"""
        if not self._windows_available():
            self.logger.warning("Fonctionnalité Windows non disponible sur cet OS.")
            return {'platform': sys.platform, 'error': 'Windows API non disponible'}
        try:
            timezone_info = None
            try:
                if hasattr(win32timezone, 'TimeZoneInformation'):
                    timezone_info = win32timezone.TimeZoneInformation()
                else:
                    # Fallback pour les versions de pywin32 qui n'ont pas TimeZoneInformation
                    timezone_info = "Non disponible"
            except:
                timezone_info = "Non disponible"
            
            return {
                'hostname': win32api.GetComputerName(),
                'os_version': win32api.GetVersionEx(),
                'system_directory': win32api.GetSystemDirectory(),
                'windows_directory': win32api.GetWindowsDirectory(),
                'processor_info': win32api.GetSystemInfo(),
                'memory_info': win32api.GlobalMemoryStatus(),
                'timezone': timezone_info,
                'current_user': win32api.GetUserName(),
                'is_admin': ctypes.windll.shell32.IsUserAnAdmin() != 0,
                'is_system': self._is_system_user()
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations système: {e}")
            return {'platform': sys.platform, 'error': str(e)}
    
    def _is_system_user(self) -> bool:
        if not self._windows_available():
            return False
        try:
            return win32api.GetUserName() == "SYSTEM"
        except:
            return False
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        if not self._windows_available():
            self.logger.warning("Fonctionnalité Windows non disponible sur cet OS.")
            return {'path': file_path, 'error': 'Windows API non disponible'}
        try:
            path = Path(file_path)
            if not path.exists():
                return {'path': str(path), 'error': 'Fichier non trouvé'}
            stat = path.stat()
            security_info = win32security.GetFileSecurity(
                str(path),
                win32security.OWNER_SECURITY_INFORMATION | 
                win32security.GROUP_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION
            )
            owner_sid = security_info.GetSecurityDescriptorOwner()
            group_sid = security_info.GetSecurityDescriptorGroup()
            dacl = security_info.GetSecurityDescriptorDacl()
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            return {
                'path': str(path),
                'name': path.name,
                'extension': path.suffix,
                'size': stat.st_size,
                'created_time': datetime.fromtimestamp(stat.st_ctime),
                'modified_time': datetime.fromtimestamp(stat.st_mtime),
                'accessed_time': datetime.fromtimestamp(stat.st_atime),
                'owner': win32security.LookupAccountSid(None, owner_sid)[0],
                'group': win32security.LookupAccountSid(None, group_sid)[0],
                'permissions': self._get_dacl_info(dacl),
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest(),
                'attributes': self._get_file_attributes(path)
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du fichier {file_path}: {e}")
            return {'path': file_path, 'error': str(e)}
    
    def _get_dacl_info(self, dacl) -> List[Dict[str, Any]]:
        if not dacl or not self._windows_available():
            return []
        permissions = []
        for i in range(dacl.GetAceCount()):
            ace_type, ace_flags, ace_mask, ace_sid = dacl.GetAce(i)
            account_name, domain_name, account_type = win32security.LookupAccountSid(None, ace_sid)
            permissions.append({
                'type': ace_type,
                'flags': ace_flags,
                'mask': ace_mask,
                'account': f"{domain_name}\\{account_name}",
                'account_type': account_type
            })
        return permissions
    
    def _get_file_attributes(self, path: Path) -> Dict[str, bool]:
        if not self._windows_available():
            return {}
        try:
            attrs = win32file.GetFileAttributes(str(path))
            return {
                'readonly': bool(attrs & win32con.FILE_ATTRIBUTE_READONLY),
                'hidden': bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN),
                'system': bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM),
                'archive': bool(attrs & win32con.FILE_ATTRIBUTE_ARCHIVE),
                'compressed': bool(attrs & win32con.FILE_ATTRIBUTE_COMPRESSED),
                'encrypted': bool(attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED),
                'temporary': bool(attrs & win32con.FILE_ATTRIBUTE_TEMPORARY),
                'offline': bool(attrs & win32con.FILE_ATTRIBUTE_OFFLINE),
                'not_content_indexed': bool(attrs & win32con.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
            }
        except:
            return {}
    
    def collect(self) -> Dict[str, Any]:
        try:
            if not self.check_privileges():
                return {
                    'system_info': self.get_system_info(),
                    'error': 'Privilèges insuffisants'
                }
            return self._collect()
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte : {e}")
            return {
                'system_info': self.get_system_info(),
                'error': str(e)
            }
    
    @abstractmethod
    def _collect(self) -> Dict[str, Any]:
        """Méthode abstraite pour la collecte de données"""
        pass 