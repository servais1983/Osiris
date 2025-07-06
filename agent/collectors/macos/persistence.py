import subprocess
import os
import plistlib
import logging
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class MacPersistenceCollector:
    """Collecte les mécanismes de persistance macOS."""
    
    def __init__(self):
        self.persistence_locations = [
            '~/Library/LaunchAgents',
            '~/Library/LaunchDaemons',
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
            '/System/Library/LaunchAgents',
            '/System/Library/LaunchDaemons'
        ]
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte tous les mécanismes de persistance."""
        results = []
        
        # Collecter les LaunchAgents et LaunchDaemons
        launch_results = self._collect_launch_items()
        results.extend(launch_results)
        
        # Collecter les Login Items
        login_results = self._collect_login_items()
        results.extend(login_results)
        
        # Collecter les Startup Items
        startup_results = self._collect_startup_items()
        results.extend(startup_results)
        
        return results
    
    def _collect_launch_items(self) -> List[Dict[str, Any]]:
        """Collecte les LaunchAgents et LaunchDaemons."""
        results = []
        
        for location in self.persistence_locations:
            expanded_path = os.path.expanduser(location)
            
            if not os.path.exists(expanded_path):
                continue
            
            try:
                for filename in os.listdir(expanded_path):
                    if filename.endswith('.plist'):
                        file_path = os.path.join(expanded_path, filename)
                        plist_info = self._parse_plist_file(file_path)
                        
                        if plist_info:
                            results.append({
                                'type': 'macos_persistence',
                                'persistence_type': 'launch_item',
                                'file_path': file_path,
                                'filename': filename,
                                'program': plist_info.get('Program'),
                                'program_arguments': plist_info.get('ProgramArguments'),
                                'run_at_load': plist_info.get('RunAtLoad', False),
                                'keep_alive': plist_info.get('KeepAlive', False),
                                'label': plist_info.get('Label'),
                                'timestamp': datetime.now().isoformat()
                            })
            
            except Exception as e:
                logger.error(f"Error collecting from {expanded_path}: {e}")
        
        return results
    
    def _parse_plist_file(self, file_path: str) -> Dict[str, Any]:
        """Parse un fichier plist."""
        try:
            with open(file_path, 'rb') as f:
                plist_data = plistlib.load(f)
            
            return plist_data
        
        except Exception as e:
            logger.error(f"Error parsing plist {file_path}: {e}")
            return {}
    
    def _collect_login_items(self) -> List[Dict[str, Any]]:
        """Collecte les Login Items."""
        results = []
        
        try:
            # Utiliser osascript pour récupérer les Login Items
            script = '''
            tell application "System Events"
                get the name of every login item
            end tell
            '''
            
            result = subprocess.run(
                ['osascript', '-e', script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                login_items = result.stdout.strip().split(', ')
                
                for item in login_items:
                    if item.strip():
                        results.append({
                            'type': 'macos_persistence',
                            'persistence_type': 'login_item',
                            'item_name': item.strip(),
                            'timestamp': datetime.now().isoformat()
                        })
        
        except subprocess.TimeoutExpired:
            logger.warning("Timeout collecting login items")
        except Exception as e:
            logger.error(f"Error collecting login items: {e}")
        
        return results
    
    def _collect_startup_items(self) -> List[Dict[str, Any]]:
        """Collecte les Startup Items."""
        results = []
        
        startup_locations = [
            '/System/Library/StartupItems',
            '/Library/StartupItems'
        ]
        
        for location in startup_locations:
            if not os.path.exists(location):
                continue
            
            try:
                for item_name in os.listdir(location):
                    item_path = os.path.join(location, item_name)
                    
                    if os.path.isdir(item_path):
                        startup_plist = os.path.join(item_path, 'StartupParameters.plist')
                        
                        if os.path.exists(startup_plist):
                            plist_info = self._parse_plist_file(startup_plist)
                            
                            results.append({
                                'type': 'macos_persistence',
                                'persistence_type': 'startup_item',
                                'item_name': item_name,
                                'item_path': item_path,
                                'provides': plist_info.get('Provides', []),
                                'requires': plist_info.get('Requires', []),
                                'timestamp': datetime.now().isoformat()
                            })
            
            except Exception as e:
                logger.error(f"Error collecting startup items from {location}: {e}")
        
        return results
    
    def get_suspicious_persistence(self) -> List[Dict[str, Any]]:
        """Identifie les mécanismes de persistance suspects."""
        all_persistence = self.collect()
        suspicious = []
        
        for item in all_persistence:
            # Vérifier les indicateurs suspects
            if self._is_suspicious(item):
                suspicious.append(item)
        
        return suspicious
    
    def _is_suspicious(self, item: Dict[str, Any]) -> bool:
        """Détermine si un mécanisme de persistance est suspect."""
        suspicious_indicators = [
            'unknown',
            'suspicious',
            'malware',
            'backdoor',
            'keylogger'
        ]
        
        # Vérifier le nom du programme
        program = item.get('program', '').lower()
        if any(indicator in program for indicator in suspicious_indicators):
            return True
        
        # Vérifier les arguments du programme
        program_args = item.get('program_arguments', [])
        for arg in program_args:
            if any(indicator in arg.lower() for indicator in suspicious_indicators):
                return True
        
        # Vérifier les chemins suspects
        file_path = item.get('file_path', '').lower()
        if any(indicator in file_path for indicator in suspicious_indicators):
            return True
        
        return False 