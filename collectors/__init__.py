"""
Module principal des collecteurs Osiris
Gestionnaire universel pour tous les collecteurs multi-OS
"""

import sys
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

# Import des gestionnaires spécifiques
try:
    from .linux import LinuxCollectorManager
except ImportError:
    LinuxCollectorManager = None

try:
    from .windows import WindowsCollectorManager
except ImportError:
    WindowsCollectorManager = None

# Import des collecteurs macOS (si disponibles)
try:
    from .macos import unified_logs, persistence
    MACOS_AVAILABLE = True
except ImportError:
    MACOS_AVAILABLE = False

logger = logging.getLogger(__name__)

class UniversalCollectorManager:
    """Gestionnaire universel pour tous les collecteurs multi-OS"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.platform = sys.platform
        self.managers = {}
        
        # Initialiser les gestionnaires selon la plateforme
        if LinuxCollectorManager and (self.platform.startswith('linux') or self.platform.startswith('freebsd')):
            self.managers['linux'] = LinuxCollectorManager()
        
        if WindowsCollectorManager and self.platform.startswith('win'):
            self.managers['windows'] = WindowsCollectorManager()
        
        if MACOS_AVAILABLE and self.platform.startswith('darwin'):
            self.managers['macos'] = self._create_macos_manager()
    
    def _create_macos_manager(self):
        """Crée un gestionnaire pour les collecteurs macOS"""
        class MacOSCollectorManager:
            def __init__(self):
                self.collectors = {
                    'unified_logs': unified_logs.UnifiedLogCollector,
                    'persistence': persistence.PersistenceCollector
                }
            
            def get_collector(self, name: str):
                if name not in self.collectors:
                    raise ValueError(f"Collecteur macOS inconnu: {name}")
                return self.collectors[name]()
            
            def list_collectors(self):
                return list(self.collectors.keys())
            
            def collect_all(self):
                results = {}
                for name, collector_class in self.collectors.items():
                    try:
                        collector = collector_class()
                        results[name] = collector.collect()
                    except Exception as e:
                        logger.error(f"Erreur lors de l'exécution du collecteur macOS {name}: {e}")
                        results[name] = {'error': str(e)}
                return results
        
        return MacOSCollectorManager()
    
    def get_available_platforms(self) -> List[str]:
        """Retourne la liste des plateformes disponibles"""
        return list(self.managers.keys())
    
    def get_collector(self, platform: str, name: str):
        """Retourne une instance du collecteur demandé pour la plateforme spécifiée"""
        if platform not in self.managers:
            raise ValueError(f"Plateforme non supportée: {platform}")
        
        return self.managers[platform].get_collector(name)
    
    def list_collectors(self, platform: Optional[str] = None) -> Dict[str, List[str]]:
        """Retourne la liste des collecteurs disponibles"""
        if platform:
            if platform not in self.managers:
                return {}
            return {platform: self.managers[platform].list_collectors()}
        
        return {platform: manager.list_collectors() 
                for platform, manager in self.managers.items()}
    
    def collect_all(self, platform: Optional[str] = None) -> Dict[str, Any]:
        """Exécute tous les collecteurs et retourne les résultats"""
        results = {
            'metadata': {
                'platform': self.platform,
                'available_platforms': self.get_available_platforms(),
                'timestamp': datetime.now().isoformat(),
                'collector_version': '1.0.0'
            },
            'results': {}
        }
        
        if platform:
            if platform not in self.managers:
                results['error'] = f"Plateforme non supportée: {platform}"
                return results
            
            try:
                results['results'][platform] = self.managers[platform].collect_all()
            except Exception as e:
                self.logger.error(f"Erreur lors de la collecte pour {platform}: {e}")
                results['results'][platform] = {'error': str(e)}
        else:
            # Collecter pour toutes les plateformes disponibles
            for platform_name, manager in self.managers.items():
                try:
                    results['results'][platform_name] = manager.collect_all()
                except Exception as e:
                    self.logger.error(f"Erreur lors de la collecte pour {platform_name}: {e}")
                    results['results'][platform_name] = {'error': str(e)}
        
        return results
    
    def collect_specific(self, platform: str, collector_name: str) -> Dict[str, Any]:
        """Exécute un collecteur spécifique"""
        try:
            # Détection automatique de la plateforme si 'auto' est spécifié
            if platform == 'auto':
                platform = self.platform
                if platform.startswith('win'):
                    platform = 'windows'
                elif platform.startswith('linux') or platform.startswith('freebsd'):
                    platform = 'linux'
                elif platform.startswith('darwin'):
                    platform = 'macos'
            
            collector = self.get_collector(platform, collector_name)
            return collector.collect()
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution du collecteur {collector_name} sur {platform}: {e}")
            return {
                'system_info': {'platform': self.platform},
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_system_info(self) -> Dict[str, Any]:
        """Retourne les informations système"""
        return {
            'platform': self.platform,
            'available_platforms': self.get_available_platforms(),
            'collectors_count': sum(len(manager.list_collectors()) 
                                  for manager in self.managers.values()),
            'timestamp': datetime.now().isoformat()
        }

# Instance globale du gestionnaire universel
universal_manager = UniversalCollectorManager()

# Fonctions d'aide pour une utilisation simplifiée
def collect_all(platform: Optional[str] = None) -> Dict[str, Any]:
    """Collecte tous les artefacts disponibles"""
    return universal_manager.collect_all(platform)

def collect_specific(platform: str, collector_name: str) -> Dict[str, Any]:
    """Collecte un artefact spécifique"""
    return universal_manager.collect_specific(platform, collector_name)

def list_collectors(platform: Optional[str] = None) -> Dict[str, List[str]]:
    """Liste tous les collecteurs disponibles"""
    return universal_manager.list_collectors(platform)

def get_system_info() -> Dict[str, Any]:
    """Retourne les informations système"""
    return universal_manager.get_system_info()

__all__ = [
    'UniversalCollectorManager',
    'universal_manager',
    'collect_all',
    'collect_specific', 
    'list_collectors',
    'get_system_info'
] 