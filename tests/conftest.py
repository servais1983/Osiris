"""
Configuration des tests multi-OS pour Osiris
Garantit que tous les tests fonctionnent sur Windows, Linux et macOS
"""

import sys
import os
import platform
from unittest.mock import Mock
import ctypes

def setup_multi_os_environment():
    """Configure l'environnement pour les tests multi-OS"""
    
    # Mock des modules Unix spécifiques sur Windows
    if platform.system() == 'Windows':
        # Modules Unix qui n'existent pas sur Windows
        unix_modules = [
            'pwd', 'grp', 'fcntl', 'termios', 'crypt', 'spwd'
        ]
        
        for module_name in unix_modules:
            if module_name not in sys.modules:
                sys.modules[module_name] = Mock()
        
        # Mock de psutil si non disponible
        if 'psutil' not in sys.modules:
            sys.modules['psutil'] = Mock()
    
    # Mock des modules Windows spécifiques sur Linux/macOS
    elif platform.system() in ['Linux', 'Darwin']:
        # Modules Windows qui n'existent pas sur Unix
        windows_modules = [
            'winreg', 'win32api', 'win32con', 'win32security',
            'win32process', 'win32event', 'win32service', 'win32serviceutil',
            'win32ts', 'win32net', 'win32netcon', 'win32profile',
            'win32cred', 'win32file', 'win32timezone', 'win32evtlog',
            'win32evtlogutil', 'win32gui', 'win32ui', 'win32print',
            'win32com', 'pythoncom', 'wmi', 'pythoncom', 'win32com'
        ]
        
        for module_name in windows_modules:
            if module_name not in sys.modules:
                sys.modules[module_name] = Mock()
        
        # Mock de ctypes.windll si non disponible
        if not hasattr(ctypes, 'windll'):
            ctypes.windll = Mock()
            ctypes.windll.shell32 = Mock()
            ctypes.windll.shell32.IsUserAnAdmin = Mock(return_value=0)
    
    # Mock des modules macOS spécifiques sur Windows/Linux
    if platform.system() != 'Darwin':
        macos_modules = [
            'plistlib', 'CoreFoundation', 'Foundation', 'AppKit',
            'Security', 'SystemConfiguration', 'LaunchServices'
        ]
        
        for module_name in macos_modules:
            if module_name not in sys.modules:
                sys.modules[module_name] = Mock()
    
    # Mock des fonctions système manquantes
    if not hasattr(os, 'geteuid'):
        os.geteuid = lambda: 0
    if not hasattr(os, 'getuid'):
        os.getuid = lambda: 0
    if not hasattr(os, 'getgid'):
        os.getgid = lambda: 0

def pytest_configure(config):
    """Configuration pytest pour les tests multi-OS"""
    setup_multi_os_environment()

def pytest_collection_modifyitems(config, items):
    """Modifie les items de test pour ajouter des marqueurs multi-OS"""
    for item in items:
        # Ajouter le marqueur multi_os à tous les tests
        item.add_marker("multi_os")
        
        # Ajouter des marqueurs spécifiques selon l'OS
        if platform.system() == 'Windows':
            item.add_marker("windows")
        elif platform.system() == 'Linux':
            item.add_marker("linux")
        elif platform.system() == 'Darwin':
            item.add_marker("macos")

# Configuration des mocks globaux pour les tests
class MockPwd:
    """Mock pour le module pwd"""
    class PasswdEntry:
        def __init__(self, name, passwd, uid, gid, gecos, dir, shell):
            self.pw_name = name
            self.pw_passwd = passwd
            self.pw_uid = uid
            self.pw_gid = gid
            self.pw_gecos = gecos
            self.pw_dir = dir
            self.pw_shell = shell
    
    def getpwall(self):
        return [
            self.PasswdEntry('root', 'x', 0, 0, 'root', '/root', '/bin/bash'),
            self.PasswdEntry('testuser', 'x', 1000, 1000, 'Test User', '/home/testuser', '/bin/bash'),
            self.PasswdEntry('admin', 'x', 1001, 1001, 'Admin User', '/home/admin', '/bin/zsh')
        ]
    
    def getpwuid(self, uid):
        for entry in self.getpwall():
            if entry.pw_uid == uid:
                return entry
        raise KeyError(f"uid {uid} not found")

class MockGrp:
    """Mock pour le module grp"""
    class GroupEntry:
        def __init__(self, name, passwd, gid, mem):
            self.gr_name = name
            self.gr_passwd = passwd
            self.gr_gid = gid
            self.gr_mem = mem
    
    def getgrall(self):
        return [
            self.GroupEntry('root', 'x', 0, ['root']),
            self.GroupEntry('users', 'x', 100, ['testuser', 'admin']),
            self.GroupEntry('sudo', 'x', 27, ['admin'])
        ]
    
    def getgrgid(self, gid):
        for entry in self.getgrall():
            if entry.gr_gid == gid:
                return entry
        raise KeyError(f"gid {gid} not found")

class MockWin32Api:
    """Mock pour win32api"""
    @staticmethod
    def GetComputerName():
        return "TESTCOMPUTER"
    
    @staticmethod
    def GetVersionEx():
        return (10, 0, 19041, 1, 2)
    
    @staticmethod
    def GetSystemDirectory():
        return "C:\\Windows\\System32"
    
    @staticmethod
    def GetWindowsDirectory():
        return "C:\\Windows"
    
    @staticmethod
    def GetSystemInfo():
        return {"ProcessorArchitecture": 9, "NumberOfProcessors": 4}
    
    @staticmethod
    def GlobalMemoryStatus():
        return {"TotalPhys": 8589934592, "AvailPhys": 4294967296}
    
    @staticmethod
    def GetUserName():
        return "testuser"
    
    @staticmethod
    def GetCurrentProcess():
        return 1234

class MockWin32Security:
    """Mock pour win32security"""
    TOKEN_ADJUST_PRIVILEGES = 32
    TOKEN_QUERY = 8
    SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege"
    SE_PRIVILEGE_ENABLED = 2
    
    @staticmethod
    def OpenProcessToken(process, flags):
        return 5678
    
    @staticmethod
    def LookupPrivilegeValue(domain, privilege):
        return 9012
    
    @staticmethod
    def AdjustTokenPrivileges(token, disable, privileges):
        pass
    
    @staticmethod
    def GetFileSecurity(path, info):
        return MockSecurityDescriptor()
    
    @staticmethod
    def LookupAccountSid(domain, sid):
        return ("testuser", "TESTDOMAIN", 1)

class MockSecurityDescriptor:
    """Mock pour SecurityDescriptor"""
    def GetSecurityDescriptorOwner(self):
        return MockSid()
    
    def GetSecurityDescriptorGroup(self):
        return MockSid()
    
    def GetSecurityDescriptorDacl(self):
        return MockDacl()

class MockSid:
    """Mock pour SID"""
    pass

class MockDacl:
    """Mock pour DACL"""
    def GetAceCount(self):
        return 2
    
    def GetAce(self, index):
        return (0, 0, 0x1f01ff, MockSid())

class MockWinReg:
    """Mock pour winreg"""
    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_CURRENT_USER = 0x80000001
    HKEY_CLASSES_ROOT = 0x80000000
    HKEY_USERS = 0x80000003
    
    @staticmethod
    def OpenKey(key, subkey, reserved=0, access=0x20019):
        return 12345
    
    @staticmethod
    def QueryValueEx(key, value_name):
        return ("test_value", 1)
    
    @staticmethod
    def EnumKey(key, index):
        return f"test_key_{index}"
    
    @staticmethod
    def CloseKey(key):
        pass

# Configuration des mocks selon l'OS
if platform.system() == 'Windows':
    # Mock pwd et grp sur Windows
    if 'pwd' in sys.modules:
        sys.modules['pwd'] = MockPwd()
    if 'grp' in sys.modules:
        sys.modules['grp'] = MockGrp()

elif platform.system() in ['Linux', 'Darwin']:
    # Mock win32api et win32security sur Linux/macOS
    if 'win32api' in sys.modules:
        sys.modules['win32api'] = MockWin32Api()
    if 'win32security' in sys.modules:
        sys.modules['win32security'] = MockWin32Security()
    if 'winreg' in sys.modules:
        sys.modules['winreg'] = MockWinReg() 