import platform
import socket
import logging
from google.protobuf.struct_pb2 import Struct

logger = logging.getLogger(__name__)

class SystemInfoSource:
    """
    Une source de données OQL qui fournit des informations de base sur le système.
    """
    def collect(self):
        """
        Collecte les données et les retourne sous forme de générateur de dictionnaires.
        Chaque 'yield' représente une ligne de résultat.
        """
        try:
            logger.debug("Début de la collecte des informations système")
            s = Struct()
            s.update({
                "hostname": socket.gethostname(),
                "os_family": platform.system(),
                "os_release": platform.release(),
                "os_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
            })
            logger.debug("Informations système collectées avec succès")
            yield s
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des informations système: {e}", exc_info=True)
            raise 