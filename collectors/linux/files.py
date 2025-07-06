"""
Collecteur pour les fichiers Linux
Collecte les informations sur les fichiers système importants
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class FilesCollector(LinuxCollector):
    """Collecteur pour les fichiers Linux"""
    
    def __init__(self):
        super().__init__()
        self.important_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/etc/resolv.conf',
            '/etc/fstab',
            '/etc/crontab',
            '/var/log/',
            '/tmp/',
            '/var/tmp/',
            '/dev/shm/',
            '/proc/',
            '/sys/',
            '/boot/',
            '/home/',
            '/root/'
        ]
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les fichiers"""
        results = {
            'system_info': self.get_system_info(),
            'important_files': {},
            'recent_files': [],
            'suspicious_files': [],
            'file_permissions': {},
            'summary': {}
        }
        
        # Collecter les fichiers importants
        results['important_files'] = self._collect_important_files()
        
        # Collecter les fichiers récents
        results['recent_files'] = self._collect_recent_files()
        
        # Analyser les fichiers suspects
        results['suspicious_files'] = self._analyze_suspicious_files(results)
        
        # Analyser les permissions
        results['file_permissions'] = self._analyze_file_permissions(results)
        
        # Générer un résumé
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _collect_important_files(self) -> Dict[str, Any]:
        """Collecte les fichiers système importants"""
        important_files = {}
        
        for path in self.important_paths:
            try:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        important_files[path] = self._analyze_file(path)
                    elif os.path.isdir(path):
                        important_files[path] = self._analyze_directory(path)
                else:
                    important_files[path] = {'exists': False}
            except Exception as e:
                self.logger.error(f"Erreur lors de l'analyse de {path}: {e}")
                important_files[path] = {'error': str(e)}
        
        return important_files
    
    def _analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyse un fichier spécifique"""
        try:
            file_info = self.get_file_info(file_path)
            
            # Lire le contenu (pour les fichiers texte)
            content = None
            if file_info.get('size', 0) < 10240:  # Limite à 10KB
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except:
                    pass
            
            return {
                'exists': True,
                'type': 'file',
                'file_info': file_info,
                'content': content,
                'lines': len(content.split('\n')) if content else 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_directory(self, dir_path: str) -> Dict[str, Any]:
        """Analyse un répertoire"""
        try:
            dir_info = self.get_file_info(dir_path)
            
            # Lister les fichiers dans le répertoire
            files = []
            subdirs = []
            
            try:
                for item in os.listdir(dir_path):
                    item_path = os.path.join(dir_path, item)
                    if os.path.isfile(item_path):
                        files.append({
                            'name': item,
                            'path': item_path,
                            'size': os.path.getsize(item_path),
                            'modified': datetime.fromtimestamp(os.path.getmtime(item_path)).isoformat()
                        })
                    elif os.path.isdir(item_path):
                        subdirs.append({
                            'name': item,
                            'path': item_path
                        })
            except PermissionError:
                pass
            
            return {
                'exists': True,
                'type': 'directory',
                'dir_info': dir_info,
                'file_count': len(files),
                'subdir_count': len(subdirs),
                'files': files[:100],  # Limiter à 100 fichiers
                'subdirs': subdirs[:50]  # Limiter à 50 sous-répertoires
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _collect_recent_files(self) -> List[Dict[str, Any]]:
        """Collecte les fichiers récemment modifiés"""
        recent_files = []
        
        try:
            # Utiliser find pour trouver les fichiers récents
            result = self.execute_command([
                'find', '/', '-type', 'f', '-mtime', '-1', 
                '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
                '-exec', 'ls', '-la', '{}', ';'
            ], timeout=30)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip():
                        # Parse: -rw-r--r-- 1 user group 1234 Jan 15 10:30 /path/to/file
                        match = re.match(r'^([drwx-]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\d+)\s+(\w+\s+\d+\s+[\d:]+)\s+(.+)$', line)
                        if match:
                            permissions, links, owner, group, size, date, path = match.groups()
                            
                            recent_files.append({
                                'path': path,
                                'permissions': permissions,
                                'owner': owner,
                                'group': group,
                                'size': int(size),
                                'modified_date': date,
                                'file_info': self.get_file_info(path)
                            })
            
            # Limiter le nombre de résultats
            recent_files = recent_files[:200]
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des fichiers récents: {e}")
        
        return recent_files
    
    def _analyze_suspicious_files(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse les fichiers suspects"""
        suspicious_files = []
        
        # Patterns de noms de fichiers suspects
        suspicious_patterns = [
            r'\b(backdoor|trojan|malware|virus|worm)\b',
            r'\b(keylogger|logger|spy)\b',
            r'\b(exploit|payload|shell)\b',
            r'\b(\.exe|\.bat|\.cmd|\.scr|\.pif)\b',
            r'\b(\.php|\.jsp|\.asp)\b',
            r'\b(\.sh|\.py|\.pl|\.rb)\b',
            r'\b(\.tmp|\.temp|\.cache)\b',
            r'\b(hidden|secret|private)\b',
            r'\b(rootkit|bootkit)\b',
            r'\b(miner|mining)\b'
        ]
        
        # Compiler les patterns
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in suspicious_patterns]
        
        # Analyser les fichiers récents
        for file_info in results.get('recent_files', []):
            suspicious_flags = []
            file_path = file_info.get('path', '')
            file_name = os.path.basename(file_path)
            
            # Vérifier le nom du fichier
            for pattern in compiled_patterns:
                if pattern.search(file_name):
                    suspicious_flags.append(f"Nom suspect: {file_name}")
            
            # Vérifier les permissions suspectes
            permissions = file_info.get('permissions', '')
            if permissions.startswith('-rwxrwxrwx') or permissions.startswith('-rwsrwsrws'):
                suspicious_flags.append("Permissions suspectes (777 ou SUID/SGID)")
            
            # Vérifier les répertoires suspects
            suspicious_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/proc', '/sys']
            if any(susp_dir in file_path for susp_dir in suspicious_dirs):
                suspicious_flags.append(f"Dans un répertoire suspect: {file_path}")
            
            # Vérifier les fichiers cachés
            if file_name.startswith('.'):
                suspicious_flags.append("Fichier caché")
            
            # Vérifier les fichiers exécutables
            if permissions and 'x' in permissions:
                suspicious_flags.append("Fichier exécutable")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_files.append({
                    'file_info': file_info,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_file_risk(suspicious_flags)
                })
        
        return suspicious_files
    
    def _assess_file_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'un fichier"""
        high_risk_flags = [
            "Nom suspect:",
            "Permissions suspectes",
            "Fichier exécutable"
        ]
        
        medium_risk_flags = [
            "Dans un répertoire suspect:",
            "Fichier caché"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _analyze_file_permissions(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse les permissions des fichiers"""
        permissions_analysis = {
            'world_writable_files': [],
            'suid_files': [],
            'sgid_files': [],
            'sticky_bit_files': [],
            'permission_summary': {}
        }
        
        try:
            # Trouver les fichiers avec permissions 777
            result = self.execute_command([
                'find', '/', '-type', 'f', '-perm', '-777',
                '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
                '-exec', 'ls', '-la', '{}', ';'
            ], timeout=30)
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        permissions_analysis['world_writable_files'].append(line.strip())
            
            # Trouver les fichiers SUID
            result = self.execute_command([
                'find', '/', '-type', 'f', '-perm', '-4000',
                '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
                '-exec', 'ls', '-la', '{}', ';'
            ], timeout=30)
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        permissions_analysis['suid_files'].append(line.strip())
            
            # Trouver les fichiers SGID
            result = self.execute_command([
                'find', '/', '-type', 'f', '-perm', '-2000',
                '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
                '-exec', 'ls', '-la', '{}', ';'
            ], timeout=30)
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        permissions_analysis['sgid_files'].append(line.strip())
            
            # Trouver les fichiers avec sticky bit
            result = self.execute_command([
                'find', '/', '-type', 'f', '-perm', '-1000',
                '-not', '-path', '/proc/*', '-not', '-path', '/sys/*',
                '-exec', 'ls', '-la', '{}', ';'
            ], timeout=30)
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        permissions_analysis['sticky_bit_files'].append(line.strip())
            
            # Générer un résumé des permissions
            permissions_analysis['permission_summary'] = {
                'world_writable_count': len(permissions_analysis['world_writable_files']),
                'suid_count': len(permissions_analysis['suid_files']),
                'sgid_count': len(permissions_analysis['sgid_files']),
                'sticky_bit_count': len(permissions_analysis['sticky_bit_files'])
            }
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse des permissions: {e}")
        
        return permissions_analysis
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des fichiers"""
        try:
            important_files = results.get('important_files', {})
            recent_files = results.get('recent_files', [])
            suspicious_files = results.get('suspicious_files', [])
            permissions = results.get('file_permissions', {})
            
            # Statistiques des fichiers importants
            important_stats = {
                'total_important_files': len(important_files),
                'existing_files': len([f for f in important_files.values() if f.get('exists', False)]),
                'missing_files': len([f for f in important_files.values() if not f.get('exists', False)])
            }
            
            # Statistiques des fichiers récents
            recent_stats = {
                'total_recent_files': len(recent_files),
                'large_files': len([f for f in recent_files if f.get('size', 0) > 1024*1024]),  # > 1MB
                'executable_files': len([f for f in recent_files if 'x' in f.get('permissions', '')])
            }
            
            # Statistiques des fichiers suspects
            suspicious_stats = {
                'total_suspicious_files': len(suspicious_files),
                'high_risk_files': len([f for f in suspicious_files if f.get('risk_level') == 'high']),
                'medium_risk_files': len([f for f in suspicious_files if f.get('risk_level') == 'medium']),
                'low_risk_files': len([f for f in suspicious_files if f.get('risk_level') == 'low'])
            }
            
            return {
                'important_files_statistics': important_stats,
                'recent_files_statistics': recent_stats,
                'suspicious_files_statistics': suspicious_stats,
                'permission_statistics': permissions.get('permission_summary', {}),
                'total_files_analyzed': len(recent_files) + len(important_files)
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 