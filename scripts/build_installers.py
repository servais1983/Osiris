import os
import sys
import subprocess
from pathlib import Path

def build_windows_installer():
    """Génère l'installateur Windows (MSI)"""
    try:
        # Installation des dépendances
        subprocess.run([
            'pip', 'install', 
            'pyinstaller',
            'wixpy'
        ], check=True)
        
        # Création du fichier spec
        subprocess.run([
            'pyinstaller',
            '--name=osiris_agent',
            '--onefile',
            '--windowed',
            '--icon=agent/assets/icon.ico',
            'agent/main.py'
        ], check=True)
        
        # Génération du MSI
        subprocess.run([
            'wixpy',
            'build',
            '--name=OsirisAgent',
            '--version=1.0.0',
            '--manufacturer=Osiris',
            '--exe=dist/osiris_agent.exe',
            '--output=dist/OsirisAgent.msi'
        ], check=True)
        
        print("✅ Installateur Windows généré avec succès")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de la génération de l'installateur Windows: {e}")
        sys.exit(1)

def build_debian_package():
    """Génère le package Debian (DEB)"""
    try:
        # Création de la structure du package
        package_dir = Path('dist/debian/osiris-agent')
        package_dir.mkdir(parents=True, exist_ok=True)
        
        # Copie des fichiers
        subprocess.run([
            'cp', '-r',
            'agent/*',
            str(package_dir / 'usr/local/bin/osiris-agent')
        ], check=True)
        
        # Création du fichier control
        control_content = """Package: osiris-agent
Version: 1.0.0
Section: utils
Priority: optional
Architecture: amd64
Depends: python3 (>= 3.9)
Maintainer: Osiris <contact@osiris.com>
Description: Agent de collecte Osiris
"""
        (package_dir / 'DEBIAN/control').write_text(control_content)
        
        # Construction du package
        subprocess.run([
            'dpkg-deb',
            '--build',
            str(package_dir),
            'dist/osiris-agent.deb'
        ], check=True)
        
        print("✅ Package Debian généré avec succès")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de la génération du package Debian: {e}")
        sys.exit(1)

def build_macos_package():
    """Génère le package macOS (PKG)"""
    try:
        # Installation des dépendances
        subprocess.run([
            'pip', 'install',
            'pyinstaller',
            'py2app'
        ], check=True)
        
        # Création du fichier setup.py
        setup_content = """from setuptools import setup

APP = ['agent/main.py']
DATA_FILES = []
OPTIONS = {
    'argv_emulation': True,
    'packages': ['osiris'],
    'iconfile': 'agent/assets/icon.icns',
    'plist': {
        'CFBundleName': 'Osiris Agent',
        'CFBundleDisplayName': 'Osiris Agent',
        'CFBundleGetInfoString': 'Osiris Agent',
        'CFBundleIdentifier': 'com.osiris.agent',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0.0',
    }
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
"""
        Path('setup.py').write_text(setup_content)
        
        # Construction de l'application
        subprocess.run([
            'python', 'setup.py', 'py2app'
        ], check=True)
        
        # Création du package
        subprocess.run([
            'productbuild',
            '--component', 'dist/Osiris Agent.app',
            '/Applications',
            'dist/OsirisAgent.pkg'
        ], check=True)
        
        print("✅ Package macOS généré avec succès")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de la génération du package macOS: {e}")
        sys.exit(1)

def main():
    """Point d'entrée principal"""
    # Création du répertoire de sortie
    Path('dist').mkdir(exist_ok=True)
    
    # Détection du système d'exploitation
    if sys.platform == 'win32':
        build_windows_installer()
    elif sys.platform == 'linux':
        build_debian_package()
    elif sys.platform == 'darwin':
        build_macos_package()
    else:
        print(f"❌ Système d'exploitation non supporté: {sys.platform}")
        sys.exit(1)

if __name__ == '__main__':
    main() 