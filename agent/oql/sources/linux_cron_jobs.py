"""
Source OQL pour les tâches cron Linux
"""

import logging
from typing import Dict, List, Any, Optional
from collectors.linux import CronJobsCollector

logger = logging.getLogger(__name__)

class LinuxCronJobsSource:
    """Source OQL pour les tâches cron Linux"""
    
    def __init__(self, user: Optional[str] = None):
        self.user = user
        self.collector = CronJobsCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les tâches cron Linux"""
        try:
            results = self.collector.collect()
            
            all_jobs = []
            
            # Tâches système
            system_crontab = results.get('system_crontab', {})
            if 'jobs' in system_crontab:
                for job in system_crontab['jobs']:
                    job['source'] = 'system_crontab'
                    job['type'] = 'system'
                    all_jobs.append(job)
            
            # Tâches utilisateur
            for username, user_crontab in results.get('user_crontabs', {}).items():
                if isinstance(user_crontab, dict) and 'jobs' in user_crontab:
                    for job in user_crontab['jobs']:
                        job['source'] = 'user_crontab'
                        job['username'] = username
                        job['type'] = 'user'
                        all_jobs.append(job)
            
            # Tâches des répertoires cron
            for dir_path, dir_info in results.get('cron_directories', {}).items():
                if isinstance(dir_info, dict) and 'files' in dir_info:
                    for file_info in dir_info['files']:
                        if file_info.get('content'):
                            for line in file_info['content']:
                                if line.strip() and not line.startswith('#'):
                                    job = {
                                        'command': line.strip(),
                                        'source': 'cron_directory',
                                        'directory': dir_path,
                                        'file': file_info['name'],
                                        'type': 'directory'
                                    }
                                    all_jobs.append(job)
            
            # Filtrer par utilisateur si spécifié
            if self.user:
                all_jobs = [job for job in all_jobs if job.get('username') == self.user]
            
            return all_jobs
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des tâches cron: {e}")
            return [] 