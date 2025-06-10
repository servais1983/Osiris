from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import win32evtlog
import win32evtlogutil
import win32security
import win32api
import win32con
import win32timezone
from .base import WindowsCollector

class WindowsEventLogCollector(WindowsCollector):
    """Collecteur pour les journaux d'événements Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
        self.log_types = [
            'Security',
            'System',
            'Application',
            'Setup',
            'ForwardedEvents'
        ]
    
    def collect(self, start_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Collecte les événements des journaux Windows"""
        if not self.check_privileges():
            return {'error': 'Privilèges insuffisants'}
        
        events = {}
        for log_type in self.log_types:
            try:
                events[log_type] = self._collect_log_events(log_type, start_time)
            except Exception as e:
                self.logger.error(f"Erreur lors de la collecte des événements {log_type}: {e}")
                events[log_type] = {'error': str(e)}
        
        return events
    
    def _collect_log_events(self, log_type: str, start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Collecte les événements d'un type de journal spécifique"""
        events = []
        handle = win32evtlog.OpenEventLog(None, log_type)
        
        try:
            while True:
                events_batch = win32evtlog.ReadEventLog(
                    handle,
                    win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                    0
                )
                
                if not events_batch:
                    break
                
                for event in events_batch:
                    event_time = datetime.fromtimestamp(event.TimeGenerated)
                    if start_time and event_time < start_time:
                        continue
                    
                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_type)
                    except:
                        message = "Impossible de formater le message"
                    
                    event_data = {
                        'event_id': event.EventID,
                        'event_type': self._get_event_type(event.EventType),
                        'event_category': event.EventCategory,
                        'source': event.SourceName,
                        'time_generated': event_time.isoformat(),
                        'time_written': datetime.fromtimestamp(event.TimeWritten).isoformat(),
                        'message': message,
                        'data': self._get_event_data(event),
                        'strings': event.StringInserts,
                        'computer': event.ComputerName,
                        'user_sid': self._get_user_sid(event),
                        'severity': self._get_event_severity(event.EventType)
                    }
                    
                    events.append(event_data)
                    
        finally:
            win32evtlog.CloseEventLog(handle)
        
        return events
    
    def _get_event_type(self, event_type: int) -> str:
        """Convertit le type d'événement en chaîne"""
        types = {
            win32evtlog.EVENTLOG_ERROR_TYPE: 'Error',
            win32evtlog.EVENTLOG_WARNING_TYPE: 'Warning',
            win32evtlog.EVENTLOG_INFORMATION_TYPE: 'Information',
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'Audit Success',
            win32evtlog.EVENTLOG_AUDIT_FAILURE: 'Audit Failure'
        }
        return types.get(event_type, 'Unknown')
    
    def _get_event_severity(self, event_type: int) -> str:
        """Détermine la sévérité de l'événement"""
        if event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            return 'High'
        elif event_type == win32evtlog.EVENTLOG_WARNING_TYPE:
            return 'Medium'
        elif event_type == win32evtlog.EVENTLOG_AUDIT_FAILURE:
            return 'High'
        elif event_type == win32evtlog.EVENTLOG_AUDIT_SUCCESS:
            return 'Low'
        else:
            return 'Info'
    
    def _get_event_data(self, event) -> Dict[str, Any]:
        """Extrait les données binaires de l'événement"""
        try:
            return {
                'raw_data': event.Data,
                'data_length': len(event.Data) if event.Data else 0
            }
        except:
            return {}
    
    def _get_user_sid(self, event) -> Optional[str]:
        """Extrait le SID de l'utilisateur de l'événement"""
        try:
            if event.UserSid:
                return win32security.ConvertSidToStringSid(event.UserSid)
        except:
            pass
        return None
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques des journaux"""
        stats = {}
        for log_type in self.log_types:
            try:
                handle = win32evtlog.OpenEventLog(None, log_type)
                try:
                    stats[log_type] = {
                        'oldest_record': win32evtlog.GetOldestEventLogRecord(handle),
                        'total_records': win32evtlog.GetNumberOfEventLogRecords(handle)
                    }
                finally:
                    win32evtlog.CloseEventLog(handle)
            except Exception as e:
                self.logger.error(f"Erreur lors de la récupération des statistiques pour {log_type}: {e}")
                stats[log_type] = {'error': str(e)}
        
        return stats
    
    def clear_log(self, log_type: str) -> bool:
        """Efface un journal d'événements"""
        if not self.check_privileges():
            return False
        
        try:
            handle = win32evtlog.OpenEventLog(None, log_type)
            try:
                win32evtlog.ClearEventLog(handle, None)
                return True
            finally:
                win32evtlog.CloseEventLog(handle)
        except Exception as e:
            self.logger.error(f"Erreur lors de l'effacement du journal {log_type}: {e}")
            return False
    
    def backup_log(self, log_type: str, backup_path: str) -> bool:
        """Sauvegarde un journal d'événements"""
        if not self.check_privileges():
            return False
        
        try:
            handle = win32evtlog.OpenEventLog(None, log_type)
            try:
                win32evtlog.BackupEventLog(handle, backup_path)
                return True
            finally:
                win32evtlog.CloseEventLog(handle)
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde du journal {log_type}: {e}")
            return False 