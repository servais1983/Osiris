import logging
import requests
import time
import json
from typing import Optional, Dict
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class VirusTotalEnricher:
    """Classe pour enrichir les données avec les informations de VirusTotal."""
    
    def __init__(self, api_key: Optional[str] = None, cache_duration: int = 86400):
        """
        Initialise l'enrichisseur VirusTotal avec une clé API optionnelle.
        
        Args:
            api_key: Clé API VirusTotal
            cache_duration: Durée de validité du cache en secondes (24h par défaut)
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.cache = {}
        self.last_request_time = 0
        self.min_request_interval = 15  # Secondes entre les requêtes (limite de l'API gratuite)
        self.cache_duration = cache_duration
        self.cache_file = Path('cache/virustotal.json')
        self._load_cache()
        
    def _load_cache(self):
        """Charge le cache depuis le fichier."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                logger.info(f"Cache VirusTotal chargé : {len(self.cache)} entrées")
        except Exception as e:
            logger.error(f"Erreur lors du chargement du cache : {e}")
            self.cache = {}
            
    def _save_cache(self):
        """Sauvegarde le cache dans le fichier."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du cache : {e}")
        
    def enrich(self, sha256_hash: str) -> Optional[int]:
        """Enrichit les données avec les informations de VirusTotal."""
        if not self.api_key:
            logging.debug("Pas de clé API VirusTotal configurée")
            return None

        # Vérifier le cache
        if sha256_hash in self.cache:
            return self.cache[sha256_hash]

        # Respecter la limite de l'API
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last_request)

        try:
            params = {'apikey': self.api_key, 'resource': sha256_hash}
            response = requests.get(f"{self.base_url}/file/report", params=params)
            response.raise_for_status()
            
            result = response.json()
            if result.get('response_code') == 1:  # Fichier trouvé
                positives = result.get('positives', 0)
                self.cache[sha256_hash] = positives
                self.last_request_time = time.time()
                return positives
            else:
                logging.warning(f"Fichier non trouvé sur VirusTotal: {sha256_hash}")
                return 0

        except requests.exceptions.RequestException as e:
            logging.error(f"Erreur lors de la requête à VirusTotal: {e}")
            return None
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'enrichissement VirusTotal: {e}")
            return None 