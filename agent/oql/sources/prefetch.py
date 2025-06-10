import os
import platform
import logging
from google.protobuf.struct_pb2 import Struct

try:
    import pypf
except ImportError:
    pypf = None

from .fs import FsSource

class PrefetchSource:
    """
    Une source de données OQL qui trouve et analyse les fichiers Prefetch de Windows.
    """
    PREFETCH_GLOB = "C:\\Windows\\Prefetch\\*.pf"

    def __init__(self):
        if not pypf:
            raise ImportError("Le module 'pypf' est requis mais non installé. Impossible d'utiliser la source 'prefetch'.")

    def collect(self):
        """
        Collecte et analyse les fichiers Prefetch.
        Ne fait rien si l'OS n'est pas Windows.
        """
        if platform.system() != "Windows":
            logging.warning("La source 'prefetch' est uniquement compatible avec Windows. La requête est ignorée.")
            return

        logging.info(f"Recherche des fichiers Prefetch avec le glob: {self.PREFETCH_GLOB}")
        
        # Nous utilisons notre propre source 'fs' pour trouver les fichiers,
        # ce qui est un excellent exemple de composition de sources.
        fs_source = FsSource(path_glob=self.PREFETCH_GLOB)
        prefetch_files = fs_source.collect()

        for file_info in prefetch_files:
            filepath = file_info.get("path")
            if not filepath:
                continue

            try:
                # Ouvrir et parser le fichier prefetch
                pf_file = pypf.file()
                pf_file.open(filepath)

                s = Struct()
                s.update({
                    "source_path": filepath,
                    "executable_filename": pf_file.executable_filename,
                    "prefetch_hash": pf_file.prefetch_hash,
                    "run_count": pf_file.run_count,
                    "last_run_time_iso": pf_file.get_last_run_time_as_datetime().isoformat() if pf_file.last_run_time else None,
                    # On peut ajouter d'autres run times si nécessaire
                    # "run_times_iso": [rt.isoformat() for rt in pf_file.get_run_times_as_datetimes()],
                    "volumes_count": pf_file.number_of_volumes,
                })
                
                # Ajouter les noms des fichiers chargés par l'exécutable
                filenames_loaded = list(pf_file.filenames)
                s.update({"filenames_loaded": filenames_loaded})

                yield s

            except Exception as e:
                logging.error(f"Impossible de parser le fichier Prefetch {filepath}: {e}", exc_info=False)
                continue 