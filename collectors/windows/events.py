from typing import Dict, List, Any, Optional
from datetime import datetime
import win32evtlog
import win32evtlogutil
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

class WindowsEventCollector(WindowsCollector):
    """Collecteur pour les événements Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
        
        # Journaux d'événements à surveiller
        self.event_logs = [
            'Application',
            'Security',
            'System',
            'Setup',
            'ForwardedEvents'
        ]
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les événements"""
        if not self._check_privileges():
            return {'error': 'Privilèges insuffisants'}
        
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'logs': self._get_event_logs(),
                'stats': self._get_event_stats()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des événements: {e}")
            return {'error': str(e)}
    
    def _get_event_logs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Récupère les journaux d'événements"""
        logs = {}
        
        for log_name in self.event_logs:
            try:
                logs[log_name] = self._get_log_events(log_name)
            except Exception as e:
                self.logger.error(f"Erreur lors de la récupération du journal {log_name}: {e}")
                logs[log_name] = []
        
        return logs
    
    def _get_log_events(self, log_name: str) -> List[Dict[str, Any]]:
        """Récupère les événements d'un journal"""
        events = []
        
        try:
            # Ouverture du journal
            log_handle = win32evtlog.OpenEventLog(None, log_name)
            
            # Récupération des événements
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events_read = win32evtlog.ReadEventLog(log_handle, flags, 0)
            
            while events_read:
                for event in events_read:
                    try:
                        event_info = self._get_event_info(event)
                        if event_info:
                            events.append(event_info)
                    except:
                        continue
                
                events_read = win32evtlog.ReadEventLog(log_handle, flags, 0)
            
            # Fermeture du journal
            win32evtlog.CloseEventLog(log_handle)
            
            return events
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des événements du journal {log_name}: {e}")
            return []
    
    def _get_event_info(self, event: Any) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un événement"""
        try:
            # Récupération des données de l'événement
            event_data = win32evtlogutil.SafeFormatMessage(event, log_name=event.SourceName)
            
            # Récupération des données binaires
            binary_data = self._get_event_binary_data(event)
            
            # Récupération des données de chaîne
            string_data = self._get_event_string_data(event)
            
            # Récupération des données de catégorie
            category_data = self._get_event_category_data(event)
            
            return {
                'record_number': event.RecordNumber,
                'time_generated': datetime.fromtimestamp(event.TimeGenerated).isoformat(),
                'time_written': datetime.fromtimestamp(event.TimeWritten).isoformat(),
                'event_id': event.EventID,
                'event_type': self._get_event_type(event.EventType),
                'event_category': event.EventCategory,
                'source_name': event.SourceName,
                'computer_name': event.ComputerName,
                'user_sid': self._get_event_user_sid(event),
                'data': event_data,
                'binary_data': binary_data,
                'string_data': string_data,
                'category_data': category_data
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de l'événement: {e}")
            return None
    
    def _get_event_binary_data(self, event: Any) -> List[int]:
        """Récupère les données binaires d'un événement"""
        try:
            return list(event.Data)
        except:
            return []
    
    def _get_event_string_data(self, event: Any) -> List[str]:
        """Récupère les données de chaîne d'un événement"""
        try:
            return list(event.StringInserts)
        except:
            return []
    
    def _get_event_category_data(self, event: Any) -> List[str]:
        """Récupère les données de catégorie d'un événement"""
        try:
            return list(event.CategoryStrings)
        except:
            return []
    
    def _get_event_user_sid(self, event: Any) -> Optional[Dict[str, Any]]:
        """Récupère le SID de l'utilisateur d'un événement"""
        try:
            if event.UserSid:
                sid = win32security.ConvertSidToStringSid(event.UserSid)
                name = win32security.LookupAccountSid(None, event.UserSid)[0]
                return {
                    'sid': sid,
                    'name': name
                }
            return None
        except:
            return None
    
    def _get_event_type(self, event_type: int) -> str:
        """Convertit le type d'événement en chaîne de caractères"""
        types = {
            win32evtlog.EVENTLOG_ERROR_TYPE: 'ERROR',
            win32evtlog.EVENTLOG_WARNING_TYPE: 'WARNING',
            win32evtlog.EVENTLOG_INFORMATION_TYPE: 'INFORMATION',
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'AUDIT_SUCCESS',
            win32evtlog.EVENTLOG_AUDIT_FAILURE: 'AUDIT_FAILURE'
        }
        return types.get(event_type, 'UNKNOWN')
    
    def _get_event_stats(self) -> Dict[str, Dict[str, Any]]:
        """Récupère les statistiques des journaux d'événements"""
        stats = {}
        
        for log_name in self.event_logs:
            try:
                stats[log_name] = self._get_log_stats(log_name)
            except Exception as e:
                self.logger.error(f"Erreur lors de la récupération des statistiques du journal {log_name}: {e}")
                stats[log_name] = {}
        
        return stats
    
    def _get_log_stats(self, log_name: str) -> Dict[str, Any]:
        """Récupère les statistiques d'un journal"""
        try:
            # Ouverture du journal
            log_handle = win32evtlog.OpenEventLog(None, log_name)
            
            # Récupération des statistiques
            stats = {
                'oldest_record': win32evtlog.GetOldestEventLogRecord(log_handle),
                'number_of_records': win32evtlog.GetNumberOfEventLogRecords(log_handle),
                'is_full': win32evtlog.IsEventLogFull(log_handle)
            }
            
            # Fermeture du journal
            win32evtlog.CloseEventLog(log_handle)
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des statistiques du journal {log_name}: {e}")
            return {}
    
    def clear_log(self, log_name: str) -> bool:
        """Efface un journal d'événements"""
        try:
            # Ouverture du journal
            log_handle = win32evtlog.OpenEventLog(None, log_name)
            
            # Effacement du journal
            win32evtlog.ClearEventLog(log_handle, None)
            
            # Fermeture du journal
            win32evtlog.CloseEventLog(log_handle)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'effacement du journal {log_name}: {e}")
            return False
    
    def backup_log(self, log_name: str, backup_path: str) -> bool:
        """Sauvegarde un journal d'événements"""
        try:
            # Ouverture du journal
            log_handle = win32evtlog.OpenEventLog(None, log_name)
            
            # Sauvegarde du journal
            win32evtlog.BackupEventLog(log_handle, backup_path)
            
            # Fermeture du journal
            win32evtlog.CloseEventLog(log_handle)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde du journal {log_name}: {e}")
            return False 