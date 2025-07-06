import sys
import platform
import logging
from typing import Dict, Any

# Importer les collecteurs par plateforme
try:
    from agent.collectors.linux import shell_history, auth_log, network_connections
    LINUX_AVAILABLE = True
except ImportError:
    LINUX_AVAILABLE = False

try:
    from agent.collectors.macos import persistence, unified_logs
    MACOS_AVAILABLE = True
except ImportError:
    MACOS_AVAILABLE = False

try:
    from agent.collectors.windows import processes, files, registry
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

from agent.oql.runner import OQLRunner

def get_platform_collectors():
    """Détecte l'OS et retourne les collecteurs appropriés."""
    os_name = platform.system()
    
    if os_name == "Linux" and LINUX_AVAILABLE:
        print("Plateforme détectée : Linux. Chargement des collecteurs Linux.")
        return {
            "shell_history": shell_history.ShellHistoryCollector(),
            "auth_logs": auth_log.AuthLogCollector(),
            "network_connections": network_connections.NetworkConnectionsCollector()
        }
    elif os_name == "Darwin" and MACOS_AVAILABLE:
        print("Plateforme détectée : macOS. Chargement des collecteurs macOS.")
        return {
            "macos_persistence": persistence.MacPersistenceCollector(),
            "macos_unified_logs": unified_logs.MacUnifiedLogsCollector()
        }
    elif os_name == "Windows" and WINDOWS_AVAILABLE:
        print("Plateforme détectée : Windows. Chargement des collecteurs Windows.")
        return {
            "processes": processes.ProcessesCollector(),
            "files": files.FilesCollector(),
            "registry": registry.RegistryCollector()
        }
    else:
        print(f"Plateforme non supportée ou collecteurs non disponibles : {os_name}")
        return {}

def setup_logging():
    """Configure le système de logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('osiris_agent.log')
        ]
    )

def main():
    """Point d'entrée principal de l'agent Osiris."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Démarrage de l'agent Osiris...")
    
    # Charger uniquement les collecteurs pertinents
    platform_collectors = get_platform_collectors()
    
    if not platform_collectors:
        logger.error("Aucun collecteur disponible pour cette plateforme")
        sys.exit(1)
    
    # Initialiser le runner OQL avec ces collecteurs
    oql_runner = OQLRunner()
    oql_runner._sources.update(platform_collectors)
    
    logger.info(f"Agent initialisé avec {len(platform_collectors)} collecteurs")
    
    # TODO: Boucle principale de l'agent
    # - Connexion au Hive
    # - Exécution des requêtes OQL
    # - Envoi des résultats
    # - Gestion des alertes
    
    logger.info("Agent Osiris prêt")

if __name__ == "__main__":
    main() 