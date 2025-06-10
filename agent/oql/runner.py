import logging
import re
from .sources.system import SystemInfoSource
from .sources.processes import ProcessesSource
from .sources.network import NetworkSource
from .sources.fs import FsSource
from .sources.prefetch import PrefetchSource
from .sources.amcache import AmcacheSource
from .sources.yara_scan import YaraScanSource

logger = logging.getLogger(__name__)

# Registre simple des sources OQL
SOURCES = {
    'system_info': SystemInfoSource,
    'processes': ProcessesSource,
    'network': NetworkSource,
    'fs': FsSource,
    'prefetch': PrefetchSource,
    'amcache': AmcacheSource,
    'yara_scan': YaraScanSource
}

class OQLRunner:
    """
    Exécute les requêtes OQL et retourne les résultats.
    Supporte actuellement la syntaxe: SELECT * FROM <source> [WHERE path = '...' AND rule = '...']
    """
    def __init__(self):
        self.sources = SOURCES

    def execute_query(self, query: str):
        """
        Exécute une requête OQL et retourne un générateur de résultats.
        """
        # Parse la requête
        match = re.match(r"SELECT \* FROM (\w+)(?:\s+WHERE\s+(.+))?", query)
        if not match:
            raise ValueError("Syntaxe OQL non supportée. Utilisez: SELECT * FROM <source> [WHERE ...]")

        source_name = match.group(1)
        where_clause = match.group(2) if match.group(2) else ""

        # Extraire les paramètres de la clause WHERE
        params = {}
        if where_clause:
            for param in where_clause.split(" AND "):
                key, value = param.split("=")
                key = key.strip()
                value = value.strip().strip("'")
                params[key] = value

        # Vérifier si la source existe
        if source_name not in self.sources:
            raise ValueError(f"Source inconnue: {source_name}")

        # Créer l'instance de la source
        source_class = self.sources[source_name]
        
        # Gestion spéciale pour les sources qui nécessitent des paramètres
        if source_name == 'fs':
            if 'path' not in params:
                raise ValueError("La source 'fs' nécessite un paramètre 'path'")
            source = source_class(params['path'])
        elif source_name == 'yara_scan':
            if 'path' not in params:
                raise ValueError("La source 'yara_scan' nécessite un paramètre 'path'")
            if 'rule' not in params and 'rule_path' not in params:
                raise ValueError("La source 'yara_scan' nécessite soit un paramètre 'rule' soit un paramètre 'rule_path'")
            
            # Déterminer si c'est une règle externe ou interne
            is_external = 'rule_path' in params
            rule_param = params.get('rule_path', params.get('rule'))
            
            source = source_class(params['path'], rule_param, is_external=is_external)
        else:
            source = source_class()

        # Exécuter la requête
        logger.info(f"Exécution de la requête: {query}")
        return source.collect() 