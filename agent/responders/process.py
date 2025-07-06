import platform
import os
import signal
import subprocess
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class ProcessResponder:
    """
    Permet d'effectuer des actions sur des processus, comme les terminer.
    """
    def __init__(self):
        self.os_name = platform.system()

    def kill_process(self, pid: int) -> Tuple[bool, str]:
        """
        Tente de terminer un processus par son PID.
        D'abord de manière "propre" (SIGTERM), puis de manière forcée (SIGKILL/TerminateProcess).
        """
        logger.info(f"Attempting to terminate process with PID: {pid}")
        try:
            # S'assurer que le PID est bien un entier
            pid = int(pid)
            
            if self.os_name in ["Linux", "Darwin"]:
                return self._kill_process_unix(pid)
            elif self.os_name == "Windows":
                return self._kill_process_windows(pid)
            else:
                return False, f"Unsupported OS: {self.os_name}"
                
        except (ProcessLookupError, PermissionError) as e:
            error_msg = f"Could not terminate process {pid}: {e}"
            logger.error(error_msg)
            return False, error_msg
        except ValueError:
            error_msg = "Invalid PID format."
            logger.error(error_msg)
            return False, error_msg

    def _kill_process_unix(self, pid: int) -> Tuple[bool, str]:
        """Termine un processus sur Linux/macOS."""
        try:
            # 1. Tentative propre (permet au processus de nettoyer)
            logger.info(f"Sending SIGTERM to PID {pid}")
            os.kill(pid, signal.SIGTERM)
            
            # On pourrait ajouter une attente et vérifier si le processus est toujours là
            # avant de passer à la manière forte.
            # time.sleep(2)
            # os.kill(pid, signal.SIGKILL)
            
            return True, f"Termination signal sent to PID {pid}."
            
        except ProcessLookupError:
            return False, f"Process with PID {pid} not found."
        except PermissionError:
            return False, f"Permission denied to terminate process {pid}."

    def _kill_process_windows(self, pid: int) -> Tuple[bool, str]:
        """Termine un processus sur Windows."""
        try:
            # Sur Windows, la commande 'taskkill' est l'équivalent.
            # /F pour forcer la terminaison.
            logger.info(f"Executing taskkill /F /PID {pid}")
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)], 
                check=True, 
                capture_output=True, 
                text=True
            )
            return True, f"Process with PID {pid} terminated: {result.stdout}"
            
        except subprocess.CalledProcessError as e:
            return False, f"Failed to terminate process {pid}: {e.stderr}"

    def list_processes(self, pattern: str = None) -> Tuple[bool, list]:
        """
        Liste les processus en cours d'exécution, optionnellement filtrés par un pattern.
        """
        try:
            if self.os_name in ["Linux", "Darwin"]:
                return self._list_processes_unix(pattern)
            elif self.os_name == "Windows":
                return self._list_processes_windows(pattern)
            else:
                return False, []
                
        except Exception as e:
            logger.error(f"Error listing processes: {e}")
            return False, []

    def _list_processes_unix(self, pattern: str = None) -> Tuple[bool, list]:
        """Liste les processus sur Linux/macOS."""
        try:
            cmd = ["ps", "aux"]
            if pattern:
                cmd.extend(["|", "grep", pattern])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                processes = []
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            processes.append({
                                'pid': parts[1],
                                'command': ' '.join(parts[10:])
                            })
                return True, processes
            else:
                return False, []
                
        except Exception as e:
            logger.error(f"Error listing Unix processes: {e}")
            return False, []

    def _list_processes_windows(self, pattern: str = None) -> Tuple[bool, list]:
        """Liste les processus sur Windows."""
        try:
            cmd = ["tasklist", "/FO", "CSV"]
            if pattern:
                cmd.extend(["/FI", f"IMAGENAME eq {pattern}"])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                processes = []
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.strip('"').split('","')
                        if len(parts) >= 2:
                            processes.append({
                                'pid': parts[1],
                                'command': parts[0]
                            })
                return True, processes
            else:
                return False, []
                
        except Exception as e:
            logger.error(f"Error listing Windows processes: {e}")
            return False, []

    def get_process_info(self, pid: int) -> Tuple[bool, dict]:
        """
        Récupère des informations détaillées sur un processus.
        """
        try:
            pid = int(pid)
            
            if self.os_name in ["Linux", "Darwin"]:
                return self._get_process_info_unix(pid)
            elif self.os_name == "Windows":
                return self._get_process_info_windows(pid)
            else:
                return False, {}
                
        except Exception as e:
            logger.error(f"Error getting process info for PID {pid}: {e}")
            return False, {}

    def _get_process_info_unix(self, pid: int) -> Tuple[bool, dict]:
        """Récupère les infos d'un processus sur Linux/macOS."""
        try:
            # Utiliser ps pour obtenir les infos détaillées
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid,ppid,user,comm,pcpu,pmem,etime"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 7:
                        return True, {
                            'pid': parts[0],
                            'ppid': parts[1],
                            'user': parts[2],
                            'command': parts[3],
                            'cpu_percent': parts[4],
                            'memory_percent': parts[5],
                            'elapsed_time': parts[6]
                        }
            
            return False, {}
            
        except Exception as e:
            logger.error(f"Error getting Unix process info: {e}")
            return False, {}

    def _get_process_info_windows(self, pid: int) -> Tuple[bool, dict]:
        """Récupère les infos d'un processus sur Windows."""
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/V"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].strip('"').split('","')
                    if len(parts) >= 8:
                        return True, {
                            'pid': parts[1],
                            'ppid': parts[2],
                            'user': parts[6],
                            'command': parts[0],
                            'cpu_time': parts[7],
                            'memory_usage': parts[4]
                        }
            
            return False, {}
            
        except Exception as e:
            logger.error(f"Error getting Windows process info: {e}")
            return False, {} 