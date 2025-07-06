"""
Source OQL pour les services systemd Linux
"""

import logging
from typing import Dict, List, Any
from collectors.linux import SystemdServicesCollector

logger = logging.getLogger(__name__)

class LinuxSystemdServicesSource:
    """Source OQL pour les services systemd Linux"""
    
    def __init__(self):
        self.collector = SystemdServicesCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les services systemd Linux"""
        try:
            results = self.collector.collect()
            
            all_services = []
            
            # Services systemd
            for service_name, service_info in results.get('services', {}).items():
                service_info['name'] = service_name
                service_info['type'] = 'systemd'
                service_info['source'] = 'linux_systemd_services'
                all_services.append(service_info)
            
            # Services en cours d'exécution
            for running_service in results.get('running_services', []):
                service_info = running_service.get('info', {})
                service_info['name'] = running_service.get('name', '')
                service_info['type'] = 'systemd_running'
                service_info['source'] = 'linux_systemd_services'
                service_info['is_running'] = True
                all_services.append(service_info)
            
            # Services en échec
            for failed_service in results.get('failed_services', []):
                service_info = failed_service.get('info', {})
                service_info['name'] = failed_service.get('name', '')
                service_info['type'] = 'systemd_failed'
                service_info['source'] = 'linux_systemd_services'
                service_info['is_failed'] = True
                all_services.append(service_info)
            
            # Services suspects
            for suspicious_service in results.get('suspicious_services', []):
                service_info = suspicious_service.get('service_info', {})
                service_info['name'] = suspicious_service.get('service_name', '')
                service_info['type'] = 'systemd_suspicious'
                service_info['source'] = 'linux_systemd_services'
                service_info['suspicious_flags'] = suspicious_service.get('suspicious_flags', [])
                service_info['risk_level'] = suspicious_service.get('risk_level', 'unknown')
                service_info['is_suspicious'] = True
                all_services.append(service_info)
            
            return all_services
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des services systemd: {e}")
            return [] 