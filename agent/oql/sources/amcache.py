import os
import platform
import logging
from google.protobuf.struct_pb2 import Struct

try:
    from Registry import Registry
except ImportError:
    Registry = None

class AmcacheSource:
    """
    Une source de données OQL qui analyse le fichier Amcache.hve de Windows.
    """
    AMCACHE_PATH = "C:\\Windows\\appcompat\\Programs\\Amcache.hve"

    def __init__(self):
        if not Registry:
            raise ImportError("Le module 'python-registry' est requis mais non installé.")

    def collect(self):
        """
        Collecte et analyse le fichier Amcache.
        Ne fait rien si l'OS n'est pas Windows ou si le fichier n'existe pas.
        """
        if platform.system() != "Windows":
            logging.warning("La source 'amcache' est uniquement compatible avec Windows. Requête ignorée.")
            return

        if not os.path.exists(self.AMCACHE_PATH):
            logging.warning(f"Fichier Amcache non trouvé à l'emplacement: {self.AMCACHE_PATH}")
            return
        
        logging.info(f"Analyse du fichier Amcache: {self.AMCACHE_PATH}")

        try:
            # python-registry peut parfois laisser des handles ouverts,
            # il est donc préférable de l'utiliser dans un bloc try/finally
            # pour s'assurer que tout est nettoyé.
            reg = Registry.Registry(self.AMCACHE_PATH)
            root = reg.root()
            # Le chemin de la clé principale peut varier, on le cherche
            amcache_root_key = None
            for key in root.subkeys():
                if "File" in key.name() and root.subkey(key.name()).subkey("0000"):
                     amcache_root_key = root.subkey(key.name())
                     break
            
            if not amcache_root_key:
                logging.error("Impossible de trouver la clé racine 'File' dans Amcache.hve")
                return

            for volume_key in amcache_root_key.subkeys():
                for file_entry_key in volume_key.subkeys():
                    try:
                        s = Struct()
                        # Les valeurs sont stockées par des ID numériques
                        file_path = file_entry_key.value("101").value()
                        sha1_hash = file_entry_key.value("15").value()
                        last_modified_time = file_entry_key.value("17").value().isoformat()
                        
                        s.update({
                            "source_path": self.AMCACHE_PATH,
                            "volume_guid": volume_key.name(),
                            "file_id": file_entry_key.name(),
                            "program_path": file_path,
                            "sha1": sha1_hash,
                            "last_modified_time_utc_iso": last_modified_time,
                        })
                        yield s
                    except Registry.RegistryValueNotFoundException:
                        # Certaines entrées peuvent être incomplètes, on les ignore
                        continue
                    except Exception as e:
                        logging.error(f"Erreur lors du traitement d'une entrée Amcache: {e}")
                        continue

        except Exception as e:
            logging.error(f"Impossible de lire ou d'analyser le fichier Amcache {self.AMCACHE_PATH}: {e}", exc_info=True) 