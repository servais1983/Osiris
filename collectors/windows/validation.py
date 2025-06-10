"""
Système de validation pour les collecteurs Windows.
"""

from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import re
import os
from pathlib import Path

class ValidationError(Exception):
    """Exception levée en cas d'erreur de validation."""
    pass

def validate_path(path: str) -> str:
    """
    Valide un chemin de fichier.
    
    Args:
        path: Chemin à valider
        
    Returns:
        Le chemin validé
        
    Raises:
        ValidationError: Si le chemin est invalide
    """
    if not path:
        raise ValidationError("Le chemin ne peut pas être vide")
    
    if not os.path.exists(path):
        raise ValidationError(f"Le chemin n'existe pas: {path}")
    
    return path

def validate_file_path(path: str) -> str:
    """
    Valide un chemin de fichier.
    
    Args:
        path: Chemin à valider
        
    Returns:
        Le chemin validé
        
    Raises:
        ValidationError: Si le chemin est invalide
    """
    path = validate_path(path)
    
    if not os.path.isfile(path):
        raise ValidationError(f"Le chemin n'est pas un fichier: {path}")
    
    return path

def validate_dir_path(path: str) -> str:
    """
    Valide un chemin de répertoire.
    
    Args:
        path: Chemin à valider
        
    Returns:
        Le chemin validé
        
    Raises:
        ValidationError: Si le chemin est invalide
    """
    path = validate_path(path)
    
    if not os.path.isdir(path):
        raise ValidationError(f"Le chemin n'est pas un répertoire: {path}")
    
    return path

def validate_pid(pid: int) -> int:
    """
    Valide un PID.
    
    Args:
        pid: PID à valider
        
    Returns:
        Le PID validé
        
    Raises:
        ValidationError: Si le PID est invalide
    """
    if not isinstance(pid, int):
        raise ValidationError("Le PID doit être un entier")
    
    if pid < 0:
        raise ValidationError("Le PID ne peut pas être négatif")
    
    return pid

def validate_port(port: int) -> int:
    """
    Valide un port.
    
    Args:
        port: Port à valider
        
    Returns:
        Le port validé
        
    Raises:
        ValidationError: Si le port est invalide
    """
    if not isinstance(port, int):
        raise ValidationError("Le port doit être un entier")
    
    if port < 0 or port > 65535:
        raise ValidationError("Le port doit être compris entre 0 et 65535")
    
    return port

def validate_ip(ip: str) -> str:
    """
    Valide une adresse IP.
    
    Args:
        ip: Adresse IP à valider
        
    Returns:
        L'adresse IP validée
        
    Raises:
        ValidationError: Si l'adresse IP est invalide
    """
    if not ip:
        raise ValidationError("L'adresse IP ne peut pas être vide")
    
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        raise ValidationError(f"Format d'adresse IP invalide: {ip}")
    
    parts = ip.split('.')
    for part in parts:
        if not 0 <= int(part) <= 255:
            raise ValidationError(f"Valeur d'octet invalide dans l'adresse IP: {ip}")
    
    return ip

def validate_mac(mac: str) -> str:
    """
    Valide une adresse MAC.
    
    Args:
        mac: Adresse MAC à valider
        
    Returns:
        L'adresse MAC validée
        
    Raises:
        ValidationError: Si l'adresse MAC est invalide
    """
    if not mac:
        raise ValidationError("L'adresse MAC ne peut pas être vide")
    
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    if not re.match(pattern, mac):
        raise ValidationError(f"Format d'adresse MAC invalide: {mac}")
    
    return mac

def validate_registry_key(key: str) -> str:
    """
    Valide une clé de registre.
    
    Args:
        key: Clé à valider
        
    Returns:
        La clé validée
        
    Raises:
        ValidationError: Si la clé est invalide
    """
    if not key:
        raise ValidationError("La clé de registre ne peut pas être vide")
    
    pattern = r'^[A-Za-z0-9_\\]+$'
    if not re.match(pattern, key):
        raise ValidationError(f"Format de clé de registre invalide: {key}")
    
    return key

def validate_service_name(name: str) -> str:
    """
    Valide un nom de service.
    
    Args:
        name: Nom à valider
        
    Returns:
        Le nom validé
        
    Raises:
        ValidationError: Si le nom est invalide
    """
    if not name:
        raise ValidationError("Le nom de service ne peut pas être vide")
    
    pattern = r'^[A-Za-z0-9_]+$'
    if not re.match(pattern, name):
        raise ValidationError(f"Format de nom de service invalide: {name}")
    
    return name

def validate_username(username: str) -> str:
    """
    Valide un nom d'utilisateur.
    
    Args:
        username: Nom à valider
        
    Returns:
        Le nom validé
        
    Raises:
        ValidationError: Si le nom est invalide
    """
    if not username:
        raise ValidationError("Le nom d'utilisateur ne peut pas être vide")
    
    pattern = r'^[A-Za-z0-9_]+$'
    if not re.match(pattern, username):
        raise ValidationError(f"Format de nom d'utilisateur invalide: {username}")
    
    return username

def validate_event_id(event_id: int) -> int:
    """
    Valide un ID d'événement.
    
    Args:
        event_id: ID à valider
        
    Returns:
        L'ID validé
        
    Raises:
        ValidationError: Si l'ID est invalide
    """
    if not isinstance(event_id, int):
        raise ValidationError("L'ID d'événement doit être un entier")
    
    if event_id < 0:
        raise ValidationError("L'ID d'événement ne peut pas être négatif")
    
    return event_id

def validate_timestamp(timestamp: Union[str, datetime]) -> datetime:
    """
    Valide un timestamp.
    
    Args:
        timestamp: Timestamp à valider
        
    Returns:
        Le timestamp validé
        
    Raises:
        ValidationError: Si le timestamp est invalide
    """
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            raise ValidationError(f"Format de timestamp invalide: {timestamp}")
    
    if not isinstance(timestamp, datetime):
        raise ValidationError("Le timestamp doit être une chaîne ISO ou un objet datetime")
    
    if timestamp > datetime.now():
        raise ValidationError("Le timestamp ne peut pas être dans le futur")
    
    return timestamp

def validate_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Valide les données collectées.
    
    Args:
        data: Données à valider
        
    Returns:
        Les données validées
        
    Raises:
        ValidationError: Si les données sont invalides
    """
    if not isinstance(data, dict):
        raise ValidationError("Les données doivent être un dictionnaire")
    
    if 'timestamp' not in data:
        raise ValidationError("Les données doivent contenir un timestamp")
    
    data['timestamp'] = validate_timestamp(data['timestamp'])
    
    return data 