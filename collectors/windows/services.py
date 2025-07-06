from typing import Dict, List, Any, Optional
from datetime import datetime
import win32serviceutil
import win32service
import win32event
import win32api
import win32security
import win32con
import win32ts
import win32net
import win32netcon
import win32profile
import win32cred
import win32security
import win32file
import win32timezone
import win32evtlog
import win32evtlogutil
import win32gui
import win32ui
import win32print
import win32com.client
import pythoncom
import yara
import hashlib
import os
from pathlib import Path
from .base import WindowsCollector

class WindowsServiceCollector(WindowsCollector):
    """Collecteur pour les services Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
    
    def collect(self) -> Dict[str, Any]:
        return super().collect()

    def _collect(self) -> Dict[str, Any]:
        results = {
            'system_info': self.get_system_info(),
            'services': [],
            'drivers': [],
            'running_services': [],
            'stopped_services': [],
            'summary': {}
        }
        
        try:
            # Collecter les services
            results['services'] = self._get_services()
            
            # Collecter les pilotes
            results['drivers'] = self._get_drivers()
            
            # Séparer les services en cours d'exécution et arrêtés
            for service in results['services']:
                if service.get('status', {}).get('state') == 'RUNNING':
                    results['running_services'].append(service)
                else:
                    results['stopped_services'].append(service)
            
            # Générer un résumé
            results['summary'] = {
                'total_services': len(results['services']),
                'total_drivers': len(results['drivers']),
                'running_services_count': len(results['running_services']),
                'stopped_services_count': len(results['stopped_services']),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services: {e}")
            results['error'] = str(e)
        
        return results
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """Récupère la liste des services"""
        services = []
        
        try:
            # Récupération de la liste des services
            service_list = win32serviceutil.EnumServices(None, None, win32service.SERVICE_WIN32)
            
            for service in service_list:
                try:
                    service_info = self._get_service_info(service[0])
                    if service_info:
                        services.append(service_info)
                except:
                    continue
            
            return services
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des services: {e}")
            return []
    
    def _get_service_info(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un service"""
        try:
            # Ouverture du service
            service_handle = win32service.OpenService(
                win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT),
                service_name,
                win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
            )
            
            # Configuration du service
            config = win32service.QueryServiceConfig(service_handle)
            
            # État du service
            status = win32service.QueryServiceStatus(service_handle)
            
            # Informations de sécurité
            security_info = self._get_service_security(service_handle)
            
            # Fermeture du handle
            win32service.CloseServiceHandle(service_handle)
            
            return {
                'name': service_name,
                'display_name': config[0],
                'type': self._get_service_type(config[1]),
                'start_type': self._get_start_type(config[2]),
                'error_control': self._get_error_control(config[3]),
                'binary_path': config[4],
                'load_order_group': config[5],
                'dependencies': config[6],
                'service_start_name': config[7],
                'status': {
                    'type': self._get_service_type(status[0]),
                    'state': self._get_service_state(status[1]),
                    'controls_accepted': self._get_controls_accepted(status[2]),
                    'exit_code': status[3],
                    'service_specific_exit_code': status[4],
                    'check_point': status[5],
                    'wait_hint': status[6],
                    'process_id': status[7],
                    'service_flags': status[8]
                },
                'security': security_info
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du service {service_name}: {e}")
            return None
    
    def _get_service_security(self, service_handle: int) -> Dict[str, Any]:
        """Récupère les informations de sécurité d'un service"""
        security_info = {}
        
        try:
            # Récupération du descripteur de sécurité
            sd = win32security.QueryServiceObjectSecurity(
                service_handle,
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.GROUP_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Propriétaire
            try:
                owner_sid = sd.GetSecurityDescriptorOwner()
                owner_name = win32security.LookupAccountSid(None, owner_sid)[0]
                security_info['owner'] = {
                    'sid': win32security.ConvertSidToStringSid(owner_sid),
                    'name': owner_name
                }
            except:
                security_info['owner'] = None
            
            # Groupe
            try:
                group_sid = sd.GetSecurityDescriptorGroup()
                group_name = win32security.LookupAccountSid(None, group_sid)[0]
                security_info['group'] = {
                    'sid': win32security.ConvertSidToStringSid(group_sid),
                    'name': group_name
                }
            except:
                security_info['group'] = None
            
            # ACL
            try:
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl:
                    aces = []
                    for i in range(dacl.GetAceCount()):
                        ace_type, ace_flags, ace_mask, ace_sid = dacl.GetAce(i)
                        try:
                            ace_name = win32security.LookupAccountSid(None, ace_sid)[0]
                            aces.append({
                                'type': self._get_ace_type(ace_type),
                                'flags': self._get_ace_flags(ace_flags),
                                'mask': self._get_ace_mask(ace_mask),
                                'sid': win32security.ConvertSidToStringSid(ace_sid),
                                'name': ace_name
                            })
                        except:
                            continue
                    security_info['acl'] = aces
                else:
                    security_info['acl'] = []
            except:
                security_info['acl'] = []
            
            return security_info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de sécurité du service: {e}")
            return {}
    
    def _get_drivers(self) -> List[Dict[str, Any]]:
        """Récupère la liste des pilotes"""
        drivers = []
        
        try:
            # Récupération de la liste des pilotes
            driver_list = win32serviceutil.EnumServices(None, None, win32service.SERVICE_DRIVER)
            
            for driver in driver_list:
                try:
                    driver_info = self._get_driver_info(driver[0])
                    if driver_info:
                        drivers.append(driver_info)
                except:
                    continue
            
            return drivers
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des pilotes: {e}")
            return []
    
    def _get_driver_info(self, driver_name: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un pilote"""
        try:
            # Ouverture du pilote
            driver_handle = win32service.OpenService(
                win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT),
                driver_name,
                win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
            )
            
            # Configuration du pilote
            config = win32service.QueryServiceConfig(driver_handle)
            
            # État du pilote
            status = win32service.QueryServiceStatus(driver_handle)
            
            # Informations de sécurité
            security_info = self._get_service_security(driver_handle)
            
            # Fermeture du handle
            win32service.CloseServiceHandle(driver_handle)
            
            return {
                'name': driver_name,
                'display_name': config[0],
                'type': self._get_service_type(config[1]),
                'start_type': self._get_start_type(config[2]),
                'error_control': self._get_error_control(config[3]),
                'binary_path': config[4],
                'load_order_group': config[5],
                'dependencies': config[6],
                'service_start_name': config[7],
                'status': {
                    'type': self._get_service_type(status[0]),
                    'state': self._get_service_state(status[1]),
                    'controls_accepted': self._get_controls_accepted(status[2]),
                    'exit_code': status[3],
                    'service_specific_exit_code': status[4],
                    'check_point': status[5],
                    'wait_hint': status[6],
                    'process_id': status[7],
                    'service_flags': status[8]
                },
                'security': security_info
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du pilote {driver_name}: {e}")
            return None
    
    def _get_service_type(self, service_type: int) -> str:
        """Convertit le type de service en chaîne de caractères"""
        types = {
            win32service.SERVICE_KERNEL_DRIVER: 'KERNEL_DRIVER',
            win32service.SERVICE_FILE_SYSTEM_DRIVER: 'FILE_SYSTEM_DRIVER',
            win32service.SERVICE_WIN32_OWN_PROCESS: 'WIN32_OWN_PROCESS',
            win32service.SERVICE_WIN32_SHARE_PROCESS: 'WIN32_SHARE_PROCESS',
            win32service.SERVICE_INTERACTIVE_PROCESS: 'INTERACTIVE_PROCESS'
        }
        return types.get(service_type, 'UNKNOWN')
    
    def _get_start_type(self, start_type: int) -> str:
        """Convertit le type de démarrage en chaîne de caractères"""
        types = {
            win32service.SERVICE_BOOT_START: 'BOOT_START',
            win32service.SERVICE_SYSTEM_START: 'SYSTEM_START',
            win32service.SERVICE_AUTO_START: 'AUTO_START',
            win32service.SERVICE_DEMAND_START: 'DEMAND_START',
            win32service.SERVICE_DISABLED: 'DISABLED'
        }
        return types.get(start_type, 'UNKNOWN')
    
    def _get_error_control(self, error_control: int) -> str:
        """Convertit le contrôle d'erreur en chaîne de caractères"""
        controls = {
            win32service.SERVICE_ERROR_IGNORE: 'IGNORE',
            win32service.SERVICE_ERROR_NORMAL: 'NORMAL',
            win32service.SERVICE_ERROR_SEVERE: 'SEVERE',
            win32service.SERVICE_ERROR_CRITICAL: 'CRITICAL'
        }
        return controls.get(error_control, 'UNKNOWN')
    
    def _get_service_state(self, state: int) -> str:
        """Convertit l'état du service en chaîne de caractères"""
        states = {
            win32service.SERVICE_STOPPED: 'STOPPED',
            win32service.SERVICE_START_PENDING: 'START_PENDING',
            win32service.SERVICE_STOP_PENDING: 'STOP_PENDING',
            win32service.SERVICE_RUNNING: 'RUNNING',
            win32service.SERVICE_CONTINUE_PENDING: 'CONTINUE_PENDING',
            win32service.SERVICE_PAUSE_PENDING: 'PAUSE_PENDING',
            win32service.SERVICE_PAUSED: 'PAUSED'
        }
        return states.get(state, 'UNKNOWN')
    
    def _get_controls_accepted(self, controls: int) -> List[str]:
        """Convertit les contrôles acceptés en liste de chaînes"""
        accepted = []
        
        if controls & win32service.SERVICE_ACCEPT_STOP:
            accepted.append('STOP')
        if controls & win32service.SERVICE_ACCEPT_PAUSE_CONTINUE:
            accepted.append('PAUSE_CONTINUE')
        if controls & win32service.SERVICE_ACCEPT_SHUTDOWN:
            accepted.append('SHUTDOWN')
        if controls & win32service.SERVICE_ACCEPT_PARAMCHANGE:
            accepted.append('PARAMCHANGE')
        if controls & win32service.SERVICE_ACCEPT_NETBINDCHANGE:
            accepted.append('NETBINDCHANGE')
        if controls & win32service.SERVICE_ACCEPT_HARDWAREPROFILECHANGE:
            accepted.append('HARDWAREPROFILECHANGE')
        if controls & win32service.SERVICE_ACCEPT_POWEREVENT:
            accepted.append('POWEREVENT')
        if controls & win32service.SERVICE_ACCEPT_SESSIONCHANGE:
            accepted.append('SESSIONCHANGE')
        if controls & win32service.SERVICE_ACCEPT_PRESHUTDOWN:
            accepted.append('PRESHUTDOWN')
        if controls & win32service.SERVICE_ACCEPT_TIMECHANGE:
            accepted.append('TIMECHANGE')
        if controls & win32service.SERVICE_ACCEPT_TRIGGEREVENT:
            accepted.append('TRIGGEREVENT')
        
        return accepted
    
    def _get_ace_type(self, ace_type: int) -> str:
        """Convertit le type d'ACE en chaîne de caractères"""
        types = {
            0: 'ACCESS_ALLOWED',
            1: 'ACCESS_DENIED',
            2: 'SYSTEM_AUDIT',
            3: 'SYSTEM_ALARM'
        }
        return types.get(ace_type, 'UNKNOWN')
    
    def _get_ace_flags(self, ace_flags: int) -> List[str]:
        """Convertit les drapeaux d'ACE en liste de chaînes"""
        flags = []
        
        if ace_flags & win32security.OBJECT_INHERIT_ACE:
            flags.append('OBJECT_INHERIT')
        if ace_flags & win32security.CONTAINER_INHERIT_ACE:
            flags.append('CONTAINER_INHERIT')
        if ace_flags & win32security.NO_PROPAGATE_INHERIT_ACE:
            flags.append('NO_PROPAGATE_INHERIT')
        if ace_flags & win32security.INHERIT_ONLY_ACE:
            flags.append('INHERIT_ONLY')
        if ace_flags & win32security.SUCCESSFUL_ACCESS_ACE_FLAG:
            flags.append('SUCCESSFUL_ACCESS')
        if ace_flags & win32security.FAILED_ACCESS_ACE_FLAG:
            flags.append('FAILED_ACCESS')
        
        return flags
    
    def _get_ace_mask(self, ace_mask: int) -> List[str]:
        """Convertit le masque d'ACE en liste de chaînes"""
        masks = []
        
        if ace_mask & win32con.GENERIC_READ:
            masks.append('GENERIC_READ')
        if ace_mask & win32con.GENERIC_WRITE:
            masks.append('GENERIC_WRITE')
        if ace_mask & win32con.GENERIC_EXECUTE:
            masks.append('GENERIC_EXECUTE')
        if ace_mask & win32con.GENERIC_ALL:
            masks.append('GENERIC_ALL')
        if ace_mask & win32con.SERVICE_QUERY_CONFIG:
            masks.append('SERVICE_QUERY_CONFIG')
        if ace_mask & win32con.SERVICE_CHANGE_CONFIG:
            masks.append('SERVICE_CHANGE_CONFIG')
        if ace_mask & win32con.SERVICE_QUERY_STATUS:
            masks.append('SERVICE_QUERY_STATUS')
        if ace_mask & win32con.SERVICE_ENUMERATE_DEPENDENTS:
            masks.append('SERVICE_ENUMERATE_DEPENDENTS')
        if ace_mask & win32con.SERVICE_START:
            masks.append('SERVICE_START')
        if ace_mask & win32con.SERVICE_STOP:
            masks.append('SERVICE_STOP')
        if ace_mask & win32con.SERVICE_PAUSE_CONTINUE:
            masks.append('SERVICE_PAUSE_CONTINUE')
        if ace_mask & win32con.SERVICE_INTERROGATE:
            masks.append('SERVICE_INTERROGATE')
        if ace_mask & win32con.SERVICE_USER_DEFINED_CONTROL:
            masks.append('SERVICE_USER_DEFINED_CONTROL')
        
        return masks 