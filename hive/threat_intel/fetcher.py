import requests
import redis
import json
import logging
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import asyncio

logger = logging.getLogger(__name__)

class ThreatIntelFetcher:
    def __init__(self, redis_client: redis.Redis):
        self.redis_client = redis_client
        self.feeds = {
            "feodo": {
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "type": "ip",
                "description": "Feodo Tracker C2 IPs",
                "update_interval": 3600  # 1 heure
            },
            "malware_bazaar": {
                "url": "https://bazaar.abuse.ch/export/txt/recent/",
                "type": "hash",
                "description": "MalwareBazaar recent hashes",
                "update_interval": 7200  # 2 heures
            },
            "urlhaus": {
                "url": "https://urlhaus.abuse.ch/downloads/text/",
                "type": "url",
                "description": "URLhaus malicious URLs",
                "update_interval": 1800  # 30 minutes
            }
        }
        self.last_update = {}

    def update_feeds(self) -> Dict[str, int]:
        """
        Télécharge les indicateurs et les charge dans Redis.
        Retourne le nombre d'indicateurs chargés par feed.
        """
        logger.info("Updating Threat Intelligence feeds...")
        results = {}
        
        for feed_name, feed_config in self.feeds.items():
            try:
                count = self._update_single_feed(feed_name, feed_config)
                results[feed_name] = count
                self.last_update[feed_name] = datetime.now()
                
            except Exception as e:
                logger.error(f"Error updating feed {feed_name}: {e}")
                results[feed_name] = 0
                
        return results

    def _update_single_feed(self, feed_name: str, feed_config: Dict) -> int:
        """Met à jour un feed spécifique."""
        logger.info(f"Updating feed: {feed_name}")
        
        try:
            response = requests.get(feed_config['url'], timeout=30)
            response.raise_for_status()
            
        except requests.RequestException as e:
            logger.error(f"Failed to download feed {feed_name}: {e}")
            return 0

        count = 0
        feed_type = feed_config['type']
        
        # Utiliser un pipeline Redis pour une insertion massive et performante
        pipeline = self.redis_client.pipeline()
        
        for line in response.text.splitlines():
            line = line.strip()
            
            # Ignorer les commentaires et lignes vides
            if line.startswith('#') or not line:
                continue
                
            # Traiter selon le type de feed
            if feed_type == "ip":
                count += self._process_ip_indicator(line, feed_config, pipeline)
            elif feed_type == "hash":
                count += self._process_hash_indicator(line, feed_config, pipeline)
            elif feed_type == "url":
                count += self._process_url_indicator(line, feed_config, pipeline)
        
        # Exécuter toutes les commandes Redis en une fois
        pipeline.execute()
        
        logger.info(f"Successfully loaded {count} {feed_type} indicators from {feed_name}")
        return count

    def _process_ip_indicator(self, ip: str, feed_config: Dict, pipeline) -> int:
        """Traite un indicateur IP."""
        # Validation basique d'IP
        if not self._is_valid_ip(ip):
            return 0
            
        # La clé sera préfixée pour éviter les collisions
        key = f"threat_intel:ip:{ip}"
        value = json.dumps({
            "source": feed_config['description'],
            "type": "malicious_ip",
            "feed": feed_config['description'],
            "added_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
        })
        
        # Expire après 7 jours
        pipeline.set(key, value, ex=7*24*3600)
        return 1

    def _process_hash_indicator(self, hash_value: str, feed_config: Dict, pipeline) -> int:
        """Traite un indicateur de hash."""
        # Validation basique de hash (MD5, SHA1, SHA256)
        if not self._is_valid_hash(hash_value):
            return 0
            
        key = f"threat_intel:hash:{hash_value}"
        value = json.dumps({
            "source": feed_config['description'],
            "type": "malware_hash",
            "feed": feed_config['description'],
            "added_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=30)).isoformat()
        })
        
        # Expire après 30 jours
        pipeline.set(key, value, ex=30*24*3600)
        return 1

    def _process_url_indicator(self, url: str, feed_config: Dict, pipeline) -> int:
        """Traite un indicateur d'URL."""
        # Validation basique d'URL
        if not self._is_valid_url(url):
            return 0
            
        key = f"threat_intel:url:{url}"
        value = json.dumps({
            "source": feed_config['description'],
            "type": "malicious_url",
            "feed": feed_config['description'],
            "added_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
        })
        
        # Expire après 7 jours
        pipeline.set(key, value, ex=7*24*3600)
        return 1

    def _is_valid_ip(self, ip: str) -> bool:
        """Valide une adresse IP."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    def _is_valid_hash(self, hash_value: str) -> bool:
        """Valide un hash."""
        # MD5: 32 caractères hex
        # SHA1: 40 caractères hex
        # SHA256: 64 caractères hex
        valid_lengths = [32, 40, 64]
        return (len(hash_value) in valid_lengths and 
                all(c in '0123456789abcdefABCDEF' for c in hash_value))

    def _is_valid_url(self, url: str) -> bool:
        """Valide une URL basique."""
        return url.startswith(('http://', 'https://'))

    def check_indicator(self, indicator_type: str, value: str) -> Optional[Dict]:
        """
        Vérifie si un indicateur est présent dans la base de renseignements.
        """
        key = f"threat_intel:{indicator_type}:{value}"
        
        try:
            result = self.redis_client.get(key)
            if result:
                return json.loads(result)
            return None
            
        except Exception as e:
            logger.error(f"Error checking indicator {key}: {e}")
            return None

    def get_statistics(self) -> Dict[str, any]:
        """Récupère les statistiques des indicateurs stockés."""
        try:
            stats = {}
            
            # Compter les indicateurs par type
            for indicator_type in ['ip', 'hash', 'url']:
                pattern = f"threat_intel:{indicator_type}:*"
                count = len(self.redis_client.keys(pattern))
                stats[f"{indicator_type}_count"] = count
            
            # Informations sur les derniers updates
            stats['last_updates'] = {
                feed_name: last_update.isoformat() if last_update else None
                for feed_name, last_update in self.last_update.items()
            }
            
            # Informations sur les feeds
            stats['feeds'] = {
                feed_name: {
                    'description': feed_config['description'],
                    'type': feed_config['type'],
                    'update_interval': feed_config['update_interval']
                }
                for feed_name, feed_config in self.feeds.items()
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def cleanup_expired_indicators(self) -> int:
        """Nettoie les indicateurs expirés."""
        try:
            # Redis gère automatiquement l'expiration, mais on peut forcer un nettoyage
            # Cette méthode peut être appelée périodiquement pour optimiser l'espace
            before_count = len(self.redis_client.keys("threat_intel:*"))
            
            # Forcer l'expiration des clés expirées
            self.redis_client.execute_command("FLUSHDB")
            
            after_count = len(self.redis_client.keys("threat_intel:*"))
            cleaned_count = before_count - after_count
            
            logger.info(f"Cleaned up {cleaned_count} expired indicators")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired indicators: {e}")
            return 0

    def add_custom_indicator(self, indicator_type: str, value: str, metadata: Dict) -> bool:
        """
        Ajoute un indicateur personnalisé à la base de renseignements.
        """
        try:
            key = f"threat_intel:{indicator_type}:{value}"
            
            # Ajouter les métadonnées par défaut
            indicator_data = {
                "source": "custom",
                "type": f"custom_{indicator_type}",
                "added_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(days=30)).isoformat(),
                **metadata
            }
            
            value_json = json.dumps(indicator_data)
            self.redis_client.set(key, value_json, ex=30*24*3600)
            
            logger.info(f"Added custom indicator: {indicator_type}:{value}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom indicator: {e}")
            return False

    async def start_periodic_updates(self, interval: int = 3600):
        """
        Démarre les mises à jour périodiques des feeds.
        """
        logger.info(f"Starting periodic threat intel updates every {interval} seconds")
        
        while True:
            try:
                self.update_feeds()
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in periodic updates: {e}")
                await asyncio.sleep(interval) 