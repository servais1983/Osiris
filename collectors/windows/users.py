from typing import Dict, List, Any, Optional
from datetime import datetime
import win32net
import win32netcon
import win32security
import win32api
import win32con
import win32ts
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
import yara
import hashlib
import os
from pathlib import Path
from .base import WindowsCollector

class WindowsUserCollector(WindowsCollector):
    """Collecteur pour les utilisateurs Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les utilisateurs"""
        if not self._check_privileges():
            return {'error': 'Privilèges insuffisants'}
        
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'users': self._get_users(),
                'groups': self._get_groups(),
                'sessions': self._get_sessions(),
                'profiles': self._get_profiles()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des utilisateurs: {e}")
            return {'error': str(e)}
    
    def _get_users(self) -> List[Dict[str, Any]]:
        """Récupère la liste des utilisateurs"""
        users = []
        
        try:
            # Récupération des utilisateurs
            user_list = win32net.NetUserEnum(None, 0)[0]
            
            for user in user_list:
                try:
                    user_info = self._get_user_info(user['name'])
                    if user_info:
                        users.append(user_info)
                except:
                    continue
            
            return users
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des utilisateurs: {e}")
            return []
    
    def _get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un utilisateur"""
        try:
            # Récupération des informations de base
            user_info = win32net.NetUserGetInfo(None, username, 3)
            
            # Récupération des groupes
            groups = self._get_user_groups(username)
            
            # Récupération des privilèges
            privileges = self._get_user_privileges(username)
            
            # Récupération des informations de sécurité
            security_info = self._get_user_security(username)
            
            return {
                'name': username,
                'full_name': user_info['full_name'],
                'comment': user_info['comment'],
                'flags': self._get_user_flags(user_info['flags']),
                'script_path': user_info['script_path'],
                'auth_flags': user_info['auth_flags'],
                'password_age': user_info['password_age'],
                'last_logon': datetime.fromtimestamp(user_info['last_logon']).isoformat() if user_info['last_logon'] else None,
                'last_logoff': datetime.fromtimestamp(user_info['last_logoff']).isoformat() if user_info['last_logoff'] else None,
                'acct_expires': datetime.fromtimestamp(user_info['acct_expires']).isoformat() if user_info['acct_expires'] else None,
                'max_storage': user_info['max_storage'],
                'units_per_week': user_info['units_per_week'],
                'logon_hours': self._get_logon_hours(user_info['logon_hours']),
                'bad_pw_count': user_info['bad_pw_count'],
                'num_logons': user_info['num_logons'],
                'logon_server': user_info['logon_server'],
                'country_code': user_info['country_code'],
                'code_page': user_info['code_page'],
                'user_id': user_info['user_id'],
                'primary_group_id': user_info['primary_group_id'],
                'profile': user_info['profile'],
                'home_dir': user_info['home_dir'],
                'home_dir_drive': user_info['home_dir_drive'],
                'groups': groups,
                'privileges': privileges,
                'security': security_info
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de l'utilisateur {username}: {e}")
            return None
    
    def _get_user_groups(self, username: str) -> List[Dict[str, Any]]:
        """Récupère les groupes d'un utilisateur"""
        groups = []
        
        try:
            # Récupération des groupes
            group_list = win32net.NetUserGetGroups(None, username)
            
            for group in group_list:
                try:
                    group_info = self._get_group_info(group['name'])
                    if group_info:
                        groups.append(group_info)
                except:
                    continue
            
            return groups
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des groupes de l'utilisateur {username}: {e}")
            return []
    
    def _get_user_privileges(self, username: str) -> List[Dict[str, Any]]:
        """Récupère les privilèges d'un utilisateur"""
        privileges = []
        
        try:
            # Récupération du SID
            sid = win32security.LookupAccountName(None, username)[0]
            
            # Ouverture du token
            token_handle = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            
            # Récupération des privilèges
            privs = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenPrivileges
            )
            
            for priv in privs:
                try:
                    priv_name = win32security.LookupPrivilegeName(None, priv[0])
                    privileges.append({
                        'name': priv_name,
                        'enabled': bool(priv[1] & win32con.SE_PRIVILEGE_ENABLED)
                    })
                except:
                    continue
            
            # Fermeture du handle
            win32api.CloseHandle(token_handle)
            
            return privileges
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des privilèges de l'utilisateur {username}: {e}")
            return []
    
    def _get_user_security(self, username: str) -> Dict[str, Any]:
        """Récupère les informations de sécurité d'un utilisateur"""
        security_info = {}
        
        try:
            # Récupération du SID
            sid = win32security.LookupAccountName(None, username)[0]
            
            # Récupération du descripteur de sécurité
            sd = win32security.GetSecurityInfo(
                win32api.GetCurrentProcess(),
                win32security.SE_KERNEL_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.GROUP_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Propriétaire
            try:
                owner_sid = sd.GetSecurityDescriptorOwner()
                owner_name = win32security.LookupAccountSid(None, owner_sid)[0]
                security_info['owner'] = {
                    'sid': win32security.ConvertSidToStringSid(owner_sid),
                    'name': owner_name
                }
            except:
                security_info['owner'] = None
            
            # Groupe
            try:
                group_sid = sd.GetSecurityDescriptorGroup()
                group_name = win32security.LookupAccountSid(None, group_sid)[0]
                security_info['group'] = {
                    'sid': win32security.ConvertSidToStringSid(group_sid),
                    'name': group_name
                }
            except:
                security_info['group'] = None
            
            # ACL
            try:
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl:
                    aces = []
                    for i in range(dacl.GetAceCount()):
                        ace_type, ace_flags, ace_mask, ace_sid = dacl.GetAce(i)
                        try:
                            ace_name = win32security.LookupAccountSid(None, ace_sid)[0]
                            aces.append({
                                'type': self._get_ace_type(ace_type),
                                'flags': self._get_ace_flags(ace_flags),
                                'mask': self._get_ace_mask(ace_mask),
                                'sid': win32security.ConvertSidToStringSid(ace_sid),
                                'name': ace_name
                            })
                        except:
                            continue
                    security_info['acl'] = aces
                else:
                    security_info['acl'] = []
            except:
                security_info['acl'] = []
            
            return security_info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de sécurité de l'utilisateur {username}: {e}")
            return {}
    
    def _get_groups(self) -> List[Dict[str, Any]]:
        """Récupère la liste des groupes"""
        groups = []
        
        try:
            # Récupération des groupes
            group_list = win32net.NetGroupEnum(None, 0)[0]
            
            for group in group_list:
                try:
                    group_info = self._get_group_info(group['name'])
                    if group_info:
                        groups.append(group_info)
                except:
                    continue
            
            return groups
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des groupes: {e}")
            return []
    
    def _get_group_info(self, groupname: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un groupe"""
        try:
            # Récupération des informations de base
            group_info = win32net.NetGroupGetInfo(None, groupname, 3)
            
            # Récupération des membres
            members = self._get_group_members(groupname)
            
            # Récupération des informations de sécurité
            security_info = self._get_group_security(groupname)
            
            return {
                'name': groupname,
                'comment': group_info['comment'],
                'group_id': group_info['group_id'],
                'attributes': group_info['attributes'],
                'members': members,
                'security': security_info
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du groupe {groupname}: {e}")
            return None
    
    def _get_group_members(self, groupname: str) -> List[Dict[str, Any]]:
        """Récupère les membres d'un groupe"""
        members = []
        
        try:
            # Récupération des membres
            member_list = win32net.NetGroupGetUsers(None, groupname)
            
            for member in member_list:
                try:
                    member_info = self._get_user_info(member['name'])
                    if member_info:
                        members.append(member_info)
                except:
                    continue
            
            return members
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des membres du groupe {groupname}: {e}")
            return []
    
    def _get_group_security(self, groupname: str) -> Dict[str, Any]:
        """Récupère les informations de sécurité d'un groupe"""
        security_info = {}
        
        try:
            # Récupération du SID
            sid = win32security.LookupAccountName(None, groupname)[0]
            
            # Récupération du descripteur de sécurité
            sd = win32security.GetSecurityInfo(
                win32api.GetCurrentProcess(),
                win32security.SE_KERNEL_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION |
                win32security.GROUP_SECURITY_INFORMATION |
                win32security.DACL_SECURITY_INFORMATION
            )
            
            # Propriétaire
            try:
                owner_sid = sd.GetSecurityDescriptorOwner()
                owner_name = win32security.LookupAccountSid(None, owner_sid)[0]
                security_info['owner'] = {
                    'sid': win32security.ConvertSidToStringSid(owner_sid),
                    'name': owner_name
                }
            except:
                security_info['owner'] = None
            
            # Groupe
            try:
                group_sid = sd.GetSecurityDescriptorGroup()
                group_name = win32security.LookupAccountSid(None, group_sid)[0]
                security_info['group'] = {
                    'sid': win32security.ConvertSidToStringSid(group_sid),
                    'name': group_name
                }
            except:
                security_info['group'] = None
            
            # ACL
            try:
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl:
                    aces = []
                    for i in range(dacl.GetAceCount()):
                        ace_type, ace_flags, ace_mask, ace_sid = dacl.GetAce(i)
                        try:
                            ace_name = win32security.LookupAccountSid(None, ace_sid)[0]
                            aces.append({
                                'type': self._get_ace_type(ace_type),
                                'flags': self._get_ace_flags(ace_flags),
                                'mask': self._get_ace_mask(ace_mask),
                                'sid': win32security.ConvertSidToStringSid(ace_sid),
                                'name': ace_name
                            })
                        except:
                            continue
                    security_info['acl'] = aces
                else:
                    security_info['acl'] = []
            except:
                security_info['acl'] = []
            
            return security_info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de sécurité du groupe {groupname}: {e}")
            return {}
    
    def _get_sessions(self) -> List[Dict[str, Any]]:
        """Récupère les sessions utilisateurs"""
        sessions = []
        
        try:
            # Récupération des sessions
            session_list = win32ts.WTSEnumerateSessions(None)
            
            for session in session_list:
                try:
                    session_info = self._get_session_info(session['SessionId'])
                    if session_info:
                        sessions.append(session_info)
                except:
                    continue
            
            return sessions
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des sessions: {e}")
            return []
    
    def _get_session_info(self, session_id: int) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'une session"""
        try:
            # Récupération des informations de base
            session_info = win32ts.WTSQuerySessionInformation(
                None,
                session_id,
                win32ts.WTS_INFO_CLASS.WTSInfoClass1
            )
            
            # Récupération des informations de connexion
            connection_info = win32ts.WTSQuerySessionInformation(
                None,
                session_id,
                win32ts.WTS_INFO_CLASS.WTSConnectState
            )
            
            # Récupération des informations de client
            client_info = win32ts.WTSQuerySessionInformation(
                None,
                session_id,
                win32ts.WTS_INFO_CLASS.WTSClientInfo
            )
            
            return {
                'id': session_id,
                'name': session_info['WinStationName'],
                'state': self._get_session_state(connection_info),
                'client': {
                    'name': client_info['ClientName'],
                    'address': client_info['ClientAddress'],
                    'display': client_info['ClientDisplay'],
                    'protocol': client_info['ClientProtocol']
                }
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations de la session {session_id}: {e}")
            return None
    
    def _get_profiles(self) -> List[Dict[str, Any]]:
        """Récupère les profils utilisateurs"""
        profiles = []
        
        try:
            # Récupération des profils
            profile_list = win32profile.EnumProfiles()
            
            for profile in profile_list:
                try:
                    profile_info = self._get_profile_info(profile)
                    if profile_info:
                        profiles.append(profile_info)
                except:
                    continue
            
            return profiles
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des profils: {e}")
            return []
    
    def _get_profile_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Récupère les informations d'un profil"""
        try:
            # Récupération des informations de base
            profile_info = win32profile.GetProfileType(username)
            
            # Récupération du chemin du profil
            profile_path = win32profile.GetUserProfileDirectory(username)
            
            # Récupération des variables d'environnement
            env_vars = win32profile.GetEnvironmentStrings()
            
            return {
                'username': username,
                'type': self._get_profile_type(profile_info),
                'path': profile_path,
                'environment': env_vars
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du profil {username}: {e}")
            return None
    
    def _get_user_flags(self, flags: int) -> List[str]:
        """Convertit les drapeaux utilisateur en liste de chaînes"""
        flag_list = []
        
        if flags & win32netcon.UF_SCRIPT:
            flag_list.append('SCRIPT')
        if flags & win32netcon.UF_ACCOUNTDISABLE:
            flag_list.append('ACCOUNTDISABLE')
        if flags & win32netcon.UF_HOMEDIR_REQUIRED:
            flag_list.append('HOMEDIR_REQUIRED')
        if flags & win32netcon.UF_LOCKOUT:
            flag_list.append('LOCKOUT')
        if flags & win32netcon.UF_PASSWD_NOTREQD:
            flag_list.append('PASSWD_NOTREQD')
        if flags & win32netcon.UF_PASSWD_CANT_CHANGE:
            flag_list.append('PASSWD_CANT_CHANGE')
        if flags & win32netcon.UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED:
            flag_list.append('ENCRYPTED_TEXT_PASSWORD_ALLOWED')
        if flags & win32netcon.UF_TEMP_DUPLICATE_ACCOUNT:
            flag_list.append('TEMP_DUPLICATE_ACCOUNT')
        if flags & win32netcon.UF_NORMAL_ACCOUNT:
            flag_list.append('NORMAL_ACCOUNT')
        if flags & win32netcon.UF_INTERDOMAIN_TRUST_ACCOUNT:
            flag_list.append('INTERDOMAIN_TRUST_ACCOUNT')
        if flags & win32netcon.UF_WORKSTATION_TRUST_ACCOUNT:
            flag_list.append('WORKSTATION_TRUST_ACCOUNT')
        if flags & win32netcon.UF_SERVER_TRUST_ACCOUNT:
            flag_list.append('SERVER_TRUST_ACCOUNT')
        if flags & win32netcon.UF_DONT_EXPIRE_PASSWD:
            flag_list.append('DONT_EXPIRE_PASSWD')
        if flags & win32netcon.UF_MNS_LOGON_ACCOUNT:
            flag_list.append('MNS_LOGON_ACCOUNT')
        if flags & win32netcon.UF_SMARTCARD_REQUIRED:
            flag_list.append('SMARTCARD_REQUIRED')
        if flags & win32netcon.UF_TRUSTED_FOR_DELEGATION:
            flag_list.append('TRUSTED_FOR_DELEGATION')
        if flags & win32netcon.UF_NOT_DELEGATED:
            flag_list.append('NOT_DELEGATED')
        if flags & win32netcon.UF_USE_DES_KEY_ONLY:
            flag_list.append('USE_DES_KEY_ONLY')
        if flags & win32netcon.UF_DONT_REQUIRE_PREAUTH:
            flag_list.append('DONT_REQUIRE_PREAUTH')
        if flags & win32netcon.UF_PASSWORD_EXPIRED:
            flag_list.append('PASSWORD_EXPIRED')
        if flags & win32netcon.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
            flag_list.append('TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION')
        
        return flag_list
    
    def _get_logon_hours(self, hours: bytes) -> List[Dict[str, Any]]:
        """Convertit les heures de connexion en liste de dictionnaires"""
        logon_hours = []
        
        try:
            # Conversion des heures
            for i in range(7):
                day_hours = []
                for j in range(24):
                    byte_index = (i * 24 + j) // 8
                    bit_index = (i * 24 + j) % 8
                    if hours[byte_index] & (1 << bit_index):
                        day_hours.append(j)
                logon_hours.append({
                    'day': i,
                    'hours': day_hours
                })
            
            return logon_hours
            
        except:
            return []
    
    def _get_session_state(self, state: int) -> str:
        """Convertit l'état de session en chaîne de caractères"""
        states = {
            win32ts.WTS_CONNECTSTATE_CLASS.WTSActive: 'ACTIVE',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSConnected: 'CONNECTED',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSConnectQuery: 'CONNECT_QUERY',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSShadow: 'SHADOW',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSDisconnected: 'DISCONNECTED',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSIdle: 'IDLE',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSListen: 'LISTEN',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSReset: 'RESET',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSDown: 'DOWN',
            win32ts.WTS_CONNECTSTATE_CLASS.WTSInit: 'INIT'
        }
        return states.get(state, 'UNKNOWN')
    
    def _get_profile_type(self, profile_type: int) -> str:
        """Convertit le type de profil en chaîne de caractères"""
        types = {
            win32profile.PT_TEMPORARY: 'TEMPORARY',
            win32profile.PT_ROAMING: 'ROAMING',
            win32profile.PT_MANDATORY: 'MANDATORY'
        }
        return types.get(profile_type, 'UNKNOWN')
    
    def _get_ace_type(self, ace_type: int) -> str:
        """Convertit le type d'ACE en chaîne de caractères"""
        types = {
            0: 'ACCESS_ALLOWED',
            1: 'ACCESS_DENIED',
            2: 'SYSTEM_AUDIT',
            3: 'SYSTEM_ALARM'
        }
        return types.get(ace_type, 'UNKNOWN')
    
    def _get_ace_flags(self, ace_flags: int) -> List[str]:
        """Convertit les drapeaux d'ACE en liste de chaînes"""
        flags = []
        
        if ace_flags & win32security.OBJECT_INHERIT_ACE:
            flags.append('OBJECT_INHERIT')
        if ace_flags & win32security.CONTAINER_INHERIT_ACE:
            flags.append('CONTAINER_INHERIT')
        if ace_flags & win32security.NO_PROPAGATE_INHERIT_ACE:
            flags.append('NO_PROPAGATE_INHERIT')
        if ace_flags & win32security.INHERIT_ONLY_ACE:
            flags.append('INHERIT_ONLY')
        if ace_flags & win32security.SUCCESSFUL_ACCESS_ACE_FLAG:
            flags.append('SUCCESSFUL_ACCESS')
        if ace_flags & win32security.FAILED_ACCESS_ACE_FLAG:
            flags.append('FAILED_ACCESS')
        
        return flags
    
    def _get_ace_mask(self, ace_mask: int) -> List[str]:
        """Convertit le masque d'ACE en liste de chaînes"""
        masks = []
        
        if ace_mask & win32con.GENERIC_READ:
            masks.append('GENERIC_READ')
        if ace_mask & win32con.GENERIC_WRITE:
            masks.append('GENERIC_WRITE')
        if ace_mask & win32con.GENERIC_EXECUTE:
            masks.append('GENERIC_EXECUTE')
        if ace_mask & win32con.GENERIC_ALL:
            masks.append('GENERIC_ALL')
        if ace_mask & win32con.USER_ALL_ACCESS:
            masks.append('USER_ALL_ACCESS')
        if ace_mask & win32con.USER_READ:
            masks.append('USER_READ')
        if ace_mask & win32con.USER_WRITE:
            masks.append('USER_WRITE')
        if ace_mask & win32con.USER_EXECUTE:
            masks.append('USER_EXECUTE')
        if ace_mask & win32con.GROUP_ALL_ACCESS:
            masks.append('GROUP_ALL_ACCESS')
        if ace_mask & win32con.GROUP_READ:
            masks.append('GROUP_READ')
        if ace_mask & win32con.GROUP_WRITE:
            masks.append('GROUP_WRITE')
        if ace_mask & win32con.GROUP_EXECUTE:
            masks.append('GROUP_EXECUTE')
        if ace_mask & win32con.OTHER_ALL_ACCESS:
            masks.append('OTHER_ALL_ACCESS')
        if ace_mask & win32con.OTHER_READ:
            masks.append('OTHER_READ')
        if ace_mask & win32con.OTHER_WRITE:
            masks.append('OTHER_WRITE')
        if ace_mask & win32con.OTHER_EXECUTE:
            masks.append('OTHER_EXECUTE')
        
        return masks 