"""
Classe de base pour les collecteurs Linux
Fournit des fonctionnalités communes et la gestion des erreurs
"""

import os
import sys
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod

# Gestion de l'import pwd selon la plateforme
try:
    import pwd
    import grp
    PWD_AVAILABLE = True
except ImportError:
    PWD_AVAILABLE = False
    # Mock pour les tests sur Windows
    class MockPwd:
        class PasswdEntry:
            def __init__(self, name, passwd, uid, gid, gecos, dir, shell):
                self.pw_name = name
                self.pw_passwd = passwd
                self.pw_uid = uid
                self.pw_gid = gid
                self.pw_gecos = gecos
                self.pw_dir = dir
                self.pw_shell = shell
        
        def getpwall(self):
            # Retourner des utilisateurs fictifs pour les tests
            return [
                self.PasswdEntry('root', 'x', 0, 0, 'root', '/root', '/bin/bash'),
                self.PasswdEntry('testuser', 'x', 1000, 1000, 'Test User', '/home/testuser', '/bin/bash'),
                self.PasswdEntry('admin', 'x', 1001, 1001, 'Admin User', '/home/admin', '/bin/zsh')
            ]
    
    pwd = MockPwd()
    grp = None

class LinuxCollector(ABC):
    """Classe de base pour tous les collecteurs Linux"""
    
    def __init__(self):
        self.logger = self._setup_logger()
        self.platform = self._detect_platform()
        self.requires_root = False
    
    def _setup_logger(self) -> logging.Logger:
        """Configure le logger pour ce collecteur"""
        logger = logging.getLogger(self.__class__.__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def _detect_platform(self) -> str:
        """Détecte la plateforme actuelle"""
        if sys.platform.startswith('linux'):
            return 'linux'
        elif sys.platform.startswith('win'):
            return 'windows'
        elif sys.platform.startswith('darwin'):
            return 'macos'
        else:
            return 'unknown'
    
    def get_system_info(self) -> Dict[str, Any]:
        """Récupère les informations système de base"""
        try:
            import platform
            import socket
            
            system_info = {
                'platform': self.platform,
                'hostname': socket.gethostname(),
                'os_name': platform.system(),
                'os_version': platform.release(),
                'architecture': platform.machine(),
                'timestamp': datetime.now().isoformat(),
                'pwd_available': PWD_AVAILABLE
            }
            
            # Ajouter des informations spécifiques à Linux si disponible
            if self.platform == 'linux' and PWD_AVAILABLE:
                try:
                    system_info.update({
                        'current_user': os.getlogin(),
                        'current_uid': os.getuid(),
                        'current_gid': os.getgid(),
                        'is_root': os.geteuid() == 0
                    })
                except:
                    pass
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des infos système: {e}")
            return {
                'platform': self.platform,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Méthode de collecte à implémenter dans les classes dérivées"""
        pass
    
    def validate_linux_environment(self) -> bool:
        """Valide que l'environnement est compatible Linux"""
        if self.platform != 'linux' and not PWD_AVAILABLE:
            self.logger.warning(
                "Ce collecteur est conçu pour Linux. "
                "Certaines fonctionnalités peuvent ne pas être disponibles."
            )
            return False
        return True
    
    def safe_file_read(self, file_path: str, encoding: str = 'utf-8') -> Optional[str]:
        """Lit un fichier de manière sécurisée"""
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    return f.read()
        except Exception as e:
            self.logger.error(f"Erreur lors de la lecture de {file_path}: {e}")
        return None
    
    def safe_file_lines(self, file_path: str, max_lines: int = 1000) -> list:
        """Lit les lignes d'un fichier de manière sécurisée"""
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.readlines()[:max_lines]
        except Exception as e:
            self.logger.error(f"Erreur lors de la lecture de {file_path}: {e}")
        return []
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Récupère les informations sur un fichier"""
        try:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                file_info = {
                    'path': file_path,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                    'permissions': oct(stat.st_mode)[-3:],
                    'owner': stat.st_uid,
                    'group': stat.st_gid
                }
                
                # Ajouter les noms d'utilisateur et de groupe si pwd est disponible
                if PWD_AVAILABLE:
                    try:
                        owner_name = pwd.getpwuid(stat.st_uid).pw_name
                        file_info['owner_name'] = owner_name
                    except:
                        pass
                    
                    if grp:
                        try:
                            group_name = grp.getgrgid(stat.st_gid).gr_name
                            file_info['group_name'] = group_name
                        except:
                            pass
                
                return file_info
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des infos de {file_path}: {e}")
        
        return {'path': file_path, 'error': 'Fichier non accessible'}
    
    def list_directory(self, directory: str, pattern: str = None) -> list:
        """Liste le contenu d'un répertoire"""
        try:
            if os.path.exists(directory) and os.path.isdir(directory):
                files = os.listdir(directory)
                if pattern:
                    import fnmatch
                    files = fnmatch.filter(files, pattern)
                return files
        except Exception as e:
            self.logger.error(f"Erreur lors de la lecture du répertoire {directory}: {e}")
        return []
    
    def get_users_list(self) -> list:
        """Récupère la liste des utilisateurs du système"""
        try:
            if PWD_AVAILABLE:
                return [user.pw_name for user in pwd.getpwall()]
            else:
                # Mode test sur Windows
                return ['root', 'testuser', 'admin']
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des utilisateurs: {e}")
            return []
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un utilisateur"""
        try:
            if PWD_AVAILABLE:
                user_info = pwd.getpwnam(username)
                return {
                    'username': user_info.pw_name,
                    'uid': user_info.pw_uid,
                    'gid': user_info.pw_gid,
                    'home_dir': user_info.pw_dir,
                    'shell': user_info.pw_shell
                }
            else:
                # Mode test sur Windows
                mock_users = {
                    'root': {'username': 'root', 'uid': 0, 'gid': 0, 'home_dir': '/root', 'shell': '/bin/bash'},
                    'testuser': {'username': 'testuser', 'uid': 1000, 'gid': 1000, 'home_dir': '/home/testuser', 'shell': '/bin/bash'},
                    'admin': {'username': 'admin', 'uid': 1001, 'gid': 1001, 'home_dir': '/home/admin', 'shell': '/bin/zsh'}
                }
                return mock_users.get(username)
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des infos utilisateur {username}: {e}")
            return None
    
    def check_privileges(self) -> bool:
        """Vérifie les privilèges nécessaires"""
        try:
            if self.requires_root:
                if self.platform == 'linux':
                    if os.geteuid() != 0:
                        self.logger.error("Privilèges root requis")
                        return False
                else:
                    self.logger.warning("Vérification des privilèges root non disponible sur cette plateforme")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification des privilèges: {e}")
            return False
    
    def execute_command(self, command: list, timeout: int = 30) -> Dict[str, Any]:
        """Exécute une commande système de manière sécurisée"""
        try:
            import subprocess
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': f'Commande expirée après {timeout} secondes',
                'success': False
            }
        except Exception as e:
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'success': False
            } 