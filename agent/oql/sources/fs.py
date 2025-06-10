import os
import glob
import logging
import datetime
import platform
import hashlib
from google.protobuf.struct_pb2 import Struct

def get_file_owner(filepath):
    """Tente de récupérer le propriétaire d'un fichier (multi-plateforme)."""
    try:
        if platform.system() == "Windows":
            # La récupération du propriétaire sous Windows est complexe et nécessite pywin32.
            # Pour l'instant, nous laissons ce champ vide.
            return "N/A"
        else:
            import pwd
            return pwd.getpwuid(os.stat(filepath).st_uid).pw_name
    except ImportError:
        return "N/A (module 'pwd' non disponible)"
    except KeyError:
        return "UID inconnu"
    except Exception:
        return "N/A"

def calculate_file_hashes(filepath):
    """
    Calcule les hachages MD5 et SHA256 d'un fichier.
    Retourne un tuple (md5, sha256) ou (None, None) en cas d'erreur.
    """
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            # Lire le fichier par blocs pour gérer les gros fichiers
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    except Exception as e:
        logging.warning(f"Impossible de calculer les hachages pour {filepath}: {e}")
        return None, None

class FsSource:
    """
    Une source de données OQL pour lister les fichiers et répertoires.
    Accepte un paramètre 'path' avec des jokers (glob).
    """
    def __init__(self, path_glob):
        if not path_glob:
            raise ValueError("Un chemin (path_glob) est requis pour la source 'fs'.")
        self.path_glob = path_glob
        logging.debug(f"Source 'fs' initialisée avec le glob: {self.path_glob}")

    def collect(self):
        """
        Collecte les informations sur les fichiers correspondant au glob.
        """
        # Utiliser recursive=True si le glob contient '**'
        is_recursive = "**" in self.path_glob
        
        try:
            # glob.iglob retourne un itérateur, ce qui est plus efficace en mémoire
            for filepath in glob.iglob(self.path_glob, recursive=is_recursive):
                try:
                    stats = os.stat(filepath)
                    
                    # Ne calculer les hachages que pour les fichiers (pas les répertoires)
                    md5_hash = None
                    sha256_hash = None
                    if os.path.isfile(filepath):
                        md5_hash, sha256_hash = calculate_file_hashes(filepath)
                    
                    s = Struct()
                    s.update({
                        "path": filepath,
                        "filename": os.path.basename(filepath),
                        "directory": os.path.dirname(filepath),
                        "is_dir": os.path.isdir(filepath),
                        "is_file": os.path.isfile(filepath),
                        "size_bytes": stats.st_size,
                        "owner": get_file_owner(filepath),
                        "mtime_iso": datetime.datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "atime_iso": datetime.datetime.fromtimestamp(stats.st_atime).isoformat(),
                        "ctime_iso": datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
                        "md5": md5_hash,
                        "sha256": sha256_hash
                    })
                    yield s

                except FileNotFoundError:
                    # Le fichier a peut-être été supprimé entre le moment où glob l'a trouvé et où on le traite.
                    continue
                except PermissionError:
                    logging.warning(f"Permission refusée pour accéder à {filepath}. Il est ignoré.")
                    continue
                except Exception as e:
                    logging.error(f"Erreur inattendue lors du traitement du fichier {filepath}: {e}")
                    continue
        except Exception as e:
            logging.error(f"Erreur lors de l'exécution du glob '{self.path_glob}': {e}") 