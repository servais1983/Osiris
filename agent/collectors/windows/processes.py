import subprocess
import psutil
import logging
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ProcessesCollector:
    """Collecte les informations sur les processus Windows."""
    
    def __init__(self):
        self.suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe'
        ]
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte tous les processus en cours d'exécution."""
        results = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'memory_info', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    
                    # Vérifier si le processus est suspect
                    is_suspicious = proc_info['name'].lower() in [p.lower() for p in self.suspicious_processes]
                    
                    result = {
                        'type': 'windows_process',
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'exe_path': proc_info['exe'],
                        'command_line': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        'username': proc_info['username'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else None,
                        'memory_mb': round(proc_info['memory_info'].rss / 1024 / 1024, 2) if proc_info['memory_info'] else 0,
                        'cpu_percent': round(proc_info['cpu_percent'], 2) if proc_info['cpu_percent'] else 0,
                        'is_suspicious': is_suspicious,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    results.append(result)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            logger.error(f"Error collecting processes: {e}")
        
        return results
    
    def get_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Récupère seulement les processus suspects."""
        all_processes = self.collect()
        return [proc for proc in all_processes if proc.get('is_suspicious', False)]
    
    def get_process_by_name(self, process_name: str) -> List[Dict[str, Any]]:
        """Récupère les processus par nom."""
        all_processes = self.collect()
        return [proc for proc in all_processes if proc.get('name', '').lower() == process_name.lower()]
    
    def get_process_by_pid(self, pid: int) -> Dict[str, Any]:
        """Récupère un processus par PID."""
        try:
            proc = psutil.Process(pid)
            proc_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'memory_info', 'cpu_percent'])
            
            return {
                'type': 'windows_process',
                'pid': proc_info['pid'],
                'name': proc_info['name'],
                'exe_path': proc_info['exe'],
                'command_line': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                'username': proc_info['username'],
                'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else None,
                'memory_mb': round(proc_info['memory_info'].rss / 1024 / 1024, 2) if proc_info['memory_info'] else 0,
                'cpu_percent': round(proc_info['cpu_percent'], 2) if proc_info['cpu_percent'] else 0,
                'timestamp': datetime.now().isoformat()
            }
        
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return {}
        except Exception as e:
            logger.error(f"Error getting process {pid}: {e}")
            return {}
    
    def get_process_tree(self, pid: int) -> Dict[str, Any]:
        """Récupère l'arbre de processus pour un PID donné."""
        try:
            proc = psutil.Process(pid)
            children = proc.children(recursive=True)
            
            tree = {
                'pid': pid,
                'name': proc.name(),
                'children': []
            }
            
            for child in children:
                tree['children'].append({
                    'pid': child.pid,
                    'name': child.name()
                })
            
            return tree
        
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return {}
        except Exception as e:
            logger.error(f"Error getting process tree for {pid}: {e}")
            return {}
    
    def kill_process(self, pid: int) -> bool:
        """Tente de tuer un processus."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Attendre un peu puis forcer si nécessaire
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            
            logger.info(f"Successfully killed process {pid}")
            return True
        
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied killing process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False 