import psutil
import datetime
import logging
from google.protobuf.struct_pb2 import Struct

logger = logging.getLogger(__name__)

class ProcessesSource:
    """
    Une source de données OQL qui fournit la liste des processus en cours.
    """
    def collect(self):
        """
        Collecte les informations sur les processus et les retourne en tant que générateur.
        """
        attrs = [
            'pid', 'ppid', 'name', 'exe', 'cmdline', 
            'create_time', 'status', 'username'
        ]
        
        for process in psutil.process_iter(attrs=attrs, ad_value=None):
            try:
                # La méthode info est un dictionnaire contenant les attributs demandés
                proc_info = process.info
                
                # Convertir le timestamp de création en format ISO 8601 pour la cohérence
                if proc_info['create_time']:
                    create_time_iso = datetime.datetime.fromtimestamp(
                        proc_info['create_time']
                    ).isoformat()
                else:
                    create_time_iso = None

                s = Struct()
                s.update({
                    "pid": proc_info['pid'],
                    "ppid": proc_info['ppid'],
                    "name": proc_info['name'],
                    "executable_path": proc_info['exe'],
                    "command_line": ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                    "creation_time_iso": create_time_iso,
                    "status": proc_info['status'],
                    "username": proc_info['username'],
                })
                yield s

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Le processus a peut-être terminé ou nous n'avons pas les droits, on l'ignore.
                logger.debug(f"Impossible d'accéder au processus PID {process.pid}, il est ignoré.")
                continue
            except Exception as e:
                logger.error(f"Erreur inattendue lors de la collecte du processus PID {process.pid}: {e}")
                continue 