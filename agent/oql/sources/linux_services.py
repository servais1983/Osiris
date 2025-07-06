"""
Source OQL pour les services Linux
"""

import logging
from typing import Dict, List, Any
from collectors.linux import ServicesCollector

logger = logging.getLogger(__name__)

class LinuxServicesSource:
    """Source OQL pour les services Linux"""
    
    def __init__(self):
        self.collector = ServicesCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les services Linux"""
        try:
            results = self.collector.collect()
            
            all_services = []
            
            # Services systemd
            for service_name, service_info in results.get('systemd_services', {}).items():
                service_info['name'] = service_name
                service_info['type'] = 'systemd'
                service_info['source'] = 'linux_services'
                all_services.append(service_info)
            
            # Services init.d
            for service_name, service_info in results.get('init_services', {}).items():
                service_info['name'] = service_name
                service_info['type'] = 'init.d'
                service_info['source'] = 'linux_services'
                all_services.append(service_info)
            
            return all_services
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des services: {e}")
            return [] 