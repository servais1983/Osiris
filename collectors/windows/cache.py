"""
Système de cache pour les collecteurs Windows.
"""

from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta
import functools
import threading
import json
import os
from pathlib import Path
import hashlib

class Cache:
    """Classe de gestion du cache."""
    
    def __init__(self, ttl: int = 300, max_size: int = 1000):
        """
        Initialise le cache.
        
        Args:
            ttl: Durée de vie des entrées en secondes (par défaut: 300)
            max_size: Taille maximale du cache en nombre d'entrées (par défaut: 1000)
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._ttl = ttl
        self._max_size = max_size
        self._lock = threading.Lock()
        self._cache_dir = Path('cache')
        self._cache_dir.mkdir(exist_ok=True)
    
    def get(self, key: str) -> Optional[Any]:
        """
        Récupère une valeur du cache.
        
        Args:
            key: Clé de la valeur à récupérer
            
        Returns:
            La valeur en cache ou None si elle n'existe pas ou est expirée
        """
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if datetime.now() < entry['expires_at']:
                    return entry['value']
                else:
                    del self._cache[key]
            return None
    
    def set(self, key: str, value: Any) -> None:
        """
        Stocke une valeur dans le cache.
        
        Args:
            key: Clé de la valeur à stocker
            value: Valeur à stocker
        """
        with self._lock:
            # Nettoyage du cache si nécessaire
            if len(self._cache) >= self._max_size:
                self._cleanup()
            
            # Stockage de la valeur
            self._cache[key] = {
                'value': value,
                'expires_at': datetime.now() + timedelta(seconds=self._ttl)
            }
            
            # Sauvegarde sur disque
            self._save_to_disk(key, value)
    
    def delete(self, key: str) -> None:
        """
        Supprime une valeur du cache.
        
        Args:
            key: Clé de la valeur à supprimer
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            
            # Suppression du fichier de cache
            cache_file = self._cache_dir / f"{key}.json"
            if cache_file.exists():
                cache_file.unlink()
    
    def clear(self) -> None:
        """Vide le cache."""
        with self._lock:
            self._cache.clear()
            
            # Suppression des fichiers de cache
            for cache_file in self._cache_dir.glob("*.json"):
                cache_file.unlink()
    
    def _cleanup(self) -> None:
        """Nettoie le cache en supprimant les entrées expirées et les plus anciennes si nécessaire."""
        now = datetime.now()
        
        # Supprimer les entrées expirées
        expired_keys = [
            key for key, entry in self._cache.items()
            if now >= entry['expires_at']
        ]
        for key in expired_keys:
            del self._cache[key]
            cache_file = self._cache_dir / f"{key}.json"
            if cache_file.exists():
                cache_file.unlink()
        
        # Si le cache est encore trop plein, supprimer les entrées les plus anciennes
        if len(self._cache) >= self._max_size:
            # Trier par date de création (la plus ancienne en premier)
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1]['expires_at'] - timedelta(seconds=self._ttl)
            )
            
            # Supprimer les entrées les plus anciennes
            keys_to_remove = sorted_entries[:len(self._cache) - self._max_size + 1]
            for key, _ in keys_to_remove:
                del self._cache[key]
                cache_file = self._cache_dir / f"{key}.json"
                if cache_file.exists():
                    cache_file.unlink()
    
    def _save_to_disk(self, key: str, value: Any) -> None:
        """
        Sauvegarde une valeur sur disque.
        
        Args:
            key: Clé de la valeur à sauvegarder
            value: Valeur à sauvegarder
        """
        cache_file = self._cache_dir / f"{key}.json"
        with cache_file.open('w') as f:
            json.dump({
                'value': value,
                'expires_at': (datetime.now() + timedelta(seconds=self._ttl)).isoformat()
            }, f)
    
    def _load_from_disk(self, key: str) -> Optional[Any]:
        """
        Charge une valeur depuis le disque.
        
        Args:
            key: Clé de la valeur à charger
            
        Returns:
            La valeur en cache ou None si elle n'existe pas ou est expirée
        """
        cache_file = self._cache_dir / f"{key}.json"
        if cache_file.exists():
            with cache_file.open('r') as f:
                entry = json.load(f)
                expires_at = datetime.fromisoformat(entry['expires_at'])
                if datetime.now() < expires_at:
                    return entry['value']
                else:
                    cache_file.unlink()
        return None

# Instance globale du cache
cache = Cache()

def cached(ttl: int = 300):
    """
    Décorateur pour mettre en cache les résultats d'une fonction.
    
    Args:
        ttl: Durée de vie des entrées en secondes (par défaut: 300)
        
    Returns:
        La fonction décorée
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Génération de la clé de cache avec hash pour éviter les caractères invalides
            key_data = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Tentative de récupération depuis le cache
            result = cache.get(key)
            if result is not None:
                return result
            
            # Exécution de la fonction
            result = func(*args, **kwargs)
            
            # Mise en cache du résultat
            cache.set(key, result)
            
            return result
        return wrapper
    return decorator

def clear_cache() -> None:
    """Vide le cache."""
    cache.clear()

def get_cache_stats() -> Dict[str, Any]:
    """
    Récupère les statistiques du cache.
    
    Returns:
        Un dictionnaire contenant les statistiques du cache
    """
    with cache._lock:
        return {
            'size': len(cache._cache),
            'max_size': cache._max_size,
            'ttl': cache._ttl,
            'cache_dir': str(cache._cache_dir)
        } 