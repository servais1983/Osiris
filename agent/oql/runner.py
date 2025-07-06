import logging
import re
import platform
from .sources.system import SystemInfoSource
from .sources.processes import ProcessesSource
from .sources.network import NetworkSource
from .sources.fs import FsSource
from .sources.prefetch import PrefetchSource
from .sources.amcache import AmcacheSource
from .sources.yara_scan import YaraScanSource

# Sources Linux
from .sources.linux_system_logs import LinuxSystemLogsSource
from .sources.linux_shell_history import LinuxShellHistorySource
from .sources.linux_processes import LinuxProcessesSource
from .sources.linux_network import LinuxNetworkSource
from .sources.linux_files import LinuxFilesSource
from .sources.linux_services import LinuxServicesSource
from .sources.linux_users import LinuxUsersSource
from .sources.linux_cron_jobs import LinuxCronJobsSource
from .sources.linux_systemd_services import LinuxSystemdServicesSource

from agent.collectors.linux.shell_history import ShellHistoryCollector
from agent.collectors.linux.auth_log import AuthLogCollector
from agent.collectors.linux.network_connections import NetworkConnectionsCollector
from agent.collectors.macos.persistence import MacPersistenceCollector
from agent.collectors.macos.unified_logs import MacUnifiedLogsCollector

logger = logging.getLogger(__name__)

# Registre des sources OQL par plateforme
SOURCES = {
    'windows': {
        'system_info': SystemInfoSource,
        'processes': ProcessesSource,
        'network': NetworkSource,
        'fs': FsSource,
        'prefetch': PrefetchSource,
        'amcache': AmcacheSource,
        'yara_scan': YaraScanSource
    },
    'linux': {
        'system_info': SystemInfoSource,
        'processes': LinuxProcessesSource,
        'network': LinuxNetworkSource,
        'fs': LinuxFilesSource,
        'yara_scan': YaraScanSource,
        'system_logs': LinuxSystemLogsSource,
        'shell_history': LinuxShellHistorySource,
        'services': LinuxServicesSource,
        'users': LinuxUsersSource,
        'cron_jobs': LinuxCronJobsSource,
        'systemd_services': LinuxSystemdServicesSource
    },
    'darwin': {
        'system_info': SystemInfoSource,
        'processes': ProcessesSource,
        'network': NetworkSource,
        'fs': FsSource,
        'yara_scan': YaraScanSource
    }
}

class OQLRunner:
    """
    Exécute les requêtes OQL et retourne les résultats.
    Supporte actuellement la syntaxe: SELECT * FROM <source> [WHERE path = '...' AND rule = '...']
    """
    def __init__(self):
        self.platform = self._detect_platform()
        self.sources = SOURCES.get(self.platform, SOURCES['linux'])  # Linux par défaut
        self._sources = {
            "processes": ProcessesCollector(),
            "files": FilesCollector(),
            "shell_history": ShellHistoryCollector(),
            "auth_logs": AuthLogCollector(),
            "network_connections": NetworkConnectionsCollector(),
            "macos_persistence": MacPersistenceCollector(),
            "macos_unified_logs": MacUnifiedLogsCollector(),
        }
        logger.info(f"OQLRunner initialisé pour la plateforme: {self.platform}")

    def _detect_platform(self) -> str:
        """Détecte la plateforme actuelle"""
        system = platform.system().lower()
        if system == 'windows':
            return 'windows'
        elif system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'darwin'
        else:
            return 'linux'  # Par défaut

    def run(self, query: str):
        # 1. Parser la requête OQL pour extraire la source et la clause WHERE
        source, where_clause = self._parse_query(query)

        # 2. Si la source est macos_unified_logs, on tente de traduire la clause WHERE en prédicat
        if source == "macos_unified_logs" and where_clause:
            predicate = self._translate_where_to_predicate(where_clause)
            results = self._sources[source].collect(predicate=predicate)
        else:
            results = self._sources[source].collect()
            # ... filtrage Python classique si besoin ...
        return results

    def _parse_query(self, query: str):
        # Squelette simplifié : à remplacer par un vrai parseur OQL
        # Ex: FROM macos_unified_logs SELECT * WHERE processImagePath ENDSWITH 'sshd'
        source = None
        where_clause = None
        query = query.strip()
        if query.upper().startswith("FROM "):
            parts = query[5:].split("SELECT", 1)
            if len(parts) == 2:
                source = parts[0].strip()
                select_and_where = parts[1].split("WHERE", 1)
                if len(select_and_where) == 2:
                    where_clause = select_and_where[1].strip()
        return source, where_clause

    def _translate_where_to_predicate(self, where_clause: str) -> str:
        # Squelette de traduction OQL->predicate (à améliorer)
        # Ex: processImagePath ENDSWITH 'sshd' -> 'processImagePath endswith "sshd"'
        # Ex: message CONTAINS 'accept' -> 'eventMessage CONTAINS "accept"'
        # Remplacement simple pour l'exemple
        predicate = where_clause.replace("CONTAINS", "CONTAINS").replace("ENDSWITH", "endswith")
        predicate = predicate.replace("'", '"')
        # Mapping OQL->Unified Log (ex: message -> eventMessage)
        predicate = predicate.replace("message", "eventMessage")
        return predicate

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
                if '=' in param:
                    key, value = param.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip("'")
                    params[key] = value

        # Vérifier si la source existe pour cette plateforme
        if source_name not in self.sources:
            available_sources = list(self.sources.keys())
            raise ValueError(f"Source '{source_name}' inconnue pour la plateforme {self.platform}. Sources disponibles: {available_sources}")

        # Créer l'instance de la source
        source_class = self.sources[source_name]
        
        # Gestion spéciale pour les sources qui nécessitent des paramètres
        if source_name == 'fs' or source_name == 'files':
            if 'path' not in params:
                raise ValueError(f"La source '{source_name}' nécessite un paramètre 'path'")
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
        elif source_name == 'system_logs':
            # Paramètres optionnels pour les logs système
            log_file = params.get('log_file', None)
            max_lines = int(params.get('max_lines', 1000))
            source = source_class(log_file=log_file, max_lines=max_lines)
        elif source_name == 'shell_history':
            # Paramètres optionnels pour l'historique shell
            username = params.get('username', None)
            shell_type = params.get('shell_type', None)
            source = source_class(username=username, shell_type=shell_type)
        elif source_name == 'cron_jobs':
            # Paramètres optionnels pour les tâches cron
            user = params.get('user', None)
            source = source_class(user=user)
        elif source_name == 'users':
            # Paramètres optionnels pour les utilisateurs
            include_shadow = params.get('include_shadow', 'true').lower() == 'true'
            source = source_class(include_shadow=include_shadow)
        else:
            source = source_class()

        # Exécuter la requête
        logger.info(f"Exécution de la requête: {query} sur {self.platform}")
        return source.collect()

    def list_sources(self) -> Dict[str, List[str]]:
        """Liste les sources disponibles par plateforme"""
        return {
            'current_platform': self.platform,
            'available_sources': list(self.sources.keys()),
            'all_platforms': {platform: list(sources.keys()) for platform, sources in SOURCES.items()}
        }

    def get_platform_info(self) -> Dict[str, Any]:
        """Retourne les informations sur la plateforme actuelle"""
        return {
            'platform': self.platform,
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        } 