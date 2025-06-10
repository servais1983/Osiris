import re
import json
import os
import logging
from typing import Dict, List, Any, Optional

def _normalize_process_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise une ligne de la source 'processes'."""
    timestamp = row.get('creation_time_iso')
    if not timestamp:
        return None
    
    summary = f"Processus démarré : {row.get('name')} (PID: {row.get('pid')}, PPID: {row.get('ppid')})"
    details = {
        "user": row.get('username'),
        "command_line": row.get('command_line')
    }
    return {
        "timestamp": timestamp,
        "source": "processes",
        "event_type": "Process Start",
        "summary": summary,
        "details": details
    }

def _normalize_fs_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise une ligne de la source 'fs'."""
    timestamp = row.get('mtime_iso') # Utiliser le 'modification time' comme référence
    if not timestamp:
        return None
        
    summary = f"Fichier modifié : {row.get('path')}"
    details = {
        "size": row.get('size_bytes'),
        "md5": row.get('md5'),
        "sha256": row.get('sha256'),
        "vt_detections": row.get('vt_detections', 'N/A')
    }
    return {
        "timestamp": timestamp,
        "source": "fs",
        "event_type": "File Modified",
        "summary": summary,
        "details": details
    }

def _normalize_prefetch_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise une ligne de la source 'prefetch'."""
    timestamp = row.get('last_run_time_iso')
    if not timestamp:
        return None
        
    summary = f"Programme exécuté (Prefetch) : {row.get('executable_filename')}"
    details = {
        "run_count": row.get('run_count'),
        "source_file": row.get('source_path')
    }
    return {
        "timestamp": timestamp,
        "source": "prefetch",
        "event_type": "Program Execution",
        "summary": summary,
        "details": details
    }

def _normalize_amcache_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise une ligne de la source 'amcache'."""
    timestamp = row.get('last_modified_time_utc_iso')
    if not timestamp:
        return None
        
    program_path = str(row.get('program_path', ''))
    program_name = program_path.split('\\')[-1] if program_path else 'Unknown'
    summary = f"Programme enregistré (AmCache) : {program_name}"
    details = {
        "program_path": program_path,
        "sha1": row.get('sha1')
    }
    return {
        "timestamp": timestamp,
        "source": "amcache",
        "event_type": "Program Execution Evidence",
        "summary": summary,
        "details": details
    }

def _normalize_network_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise une ligne de la source 'network'."""
    timestamp = row.get('timestamp_iso')
    if not timestamp:
        return None
        
    summary = f"Connexion réseau : {row.get('local_address')}:{row.get('local_port')} -> {row.get('remote_address')}:{row.get('remote_port')}"
    details = {
        "protocol": row.get('protocol'),
        "state": row.get('state'),
        "process": row.get('process_name'),
        "pid": row.get('pid')
    }
    return {
        "timestamp": timestamp,
        "source": "network",
        "event_type": "Network Connection",
        "summary": summary,
        "details": details
    }

def _normalize_yara_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise une ligne de la source 'yara'."""
    timestamp = row.get('scan_time_iso')
    if not timestamp:
        return None
        
    summary = f"Match YARA : {row.get('rule_name')} sur {row.get('file_path')}"
    details = {
        "tags": row.get('tags', []),
        "matched_strings": row.get('matched_strings', []),
        "vt_detections": row.get('vt_detections', 'N/A')
    }
    return {
        "timestamp": timestamp,
        "source": "yara",
        "event_type": "YARA Match",
        "summary": summary,
        "details": details
    }

# Registre des normalisateurs
# La clé est extraite de la requête OQL (ex: 'SELECT * FROM processes')
NORMALIZERS = {
    "processes": _normalize_process_row,
    "fs": _normalize_fs_row,
    "prefetch": _normalize_prefetch_row,
    "amcache": _normalize_amcache_row,
    "network": _normalize_network_row,
    "yara": _normalize_yara_row
}

def normalize_results_to_timeline(raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prend une liste de résultats bruts de la BDD et les transforme en une timeline unifiée.
    
    Args:
        raw_results: Liste des résultats bruts de la base de données
        
    Returns:
        Liste des événements normalisés, triés par ordre chronologique
    """
    timeline_events = []
    
    for raw_result in raw_results:
        query_string = raw_result.get('query_string', '')
        # Extraire le nom de la source depuis la requête
        match = re.search(r"FROM\s+([a-zA-Z_]\w*)", query_string, re.IGNORECASE)
        if not match:
            continue
        
        source_name = match.group(1).lower()
        
        if source_name in NORMALIZERS:
            normalizer_func = NORMALIZERS[source_name]
            try:
                # Les données sont stockées en JSON dans la BDD
                data_dict = json.loads(raw_result['data'])
                normalized_event = normalizer_func(data_dict)
                if normalized_event:
                    timeline_events.append(normalized_event)
            except Exception as e:
                logging.error(f"Erreur lors de la normalisation d'une ligne de '{source_name}': {e}")

    # Trier la timeline finale par ordre chronologique
    timeline_events.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return timeline_events 