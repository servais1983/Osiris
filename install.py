#!/usr/bin/env python3
"""
Script d'installation automatique pour Osiris
Détecte la plateforme et installe les dépendances appropriées
"""

import sys
import subprocess
import platform
import os

def print_banner():
    """Affiche la bannière d'installation"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                    🚀 OSIRIS INSTALLER 🚀                    ║
    ║                                                              ║
    ║           Installation automatique des dépendances           ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Vérifie la version de Python"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ requis. Version actuelle:", sys.version)
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
    return True

def detect_platform():
    """Détecte la plateforme"""
    system = platform.system()
    print(f"🔍 Plateforme détectée: {system}")
    return system.lower()

def install_package(package, description=""):
    """Installe un package avec gestion d'erreur"""
    try:
        print(f"📦 Installation de {package}...", end=" ")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅")
        return True
    except subprocess.CalledProcessError:
        print("❌")
        return False

def install_requirements():
    """Installe les dépendances de base"""
    print("\n📋 Installation des dépendances de base...")
    
    base_packages = [
        "psutil>=5.9.0",
        "typing-extensions>=4.0.0"
    ]
    
    for package in base_packages:
        install_package(package)

def install_platform_specific(platform_name):
    """Installe les dépendances spécifiques à la plateforme"""
    print(f"\n🔧 Installation des dépendances {platform_name}...")
    
    if platform_name == "windows":
        windows_packages = [
            "pywin32>=306",
            "wmi>=1.5.1"
        ]
        for package in windows_packages:
            install_package(package, f"Module Windows: {package}")
    
    elif platform_name == "linux":
        linux_packages = [
            "python-prctl>=1.7.1"
        ]
        for package in linux_packages:
            install_package(package, f"Module Linux: {package}")
    
    elif platform_name == "darwin":
        macos_packages = [
            "pyobjc-framework-SystemConfiguration>=9.0"
        ]
        for package in macos_packages:
            install_package(package, f"Module macOS: {package}")

def create_directories():
    """Crée les répertoires nécessaires"""
    print("\n📁 Création des répertoires...")
    
    directories = [
        "output",
        "logs",
        "config"
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Répertoire créé: {directory}")
        except Exception as e:
            print(f"❌ Erreur création {directory}: {e}")

def test_installation():
    """Teste l'installation"""
    print("\n🧪 Test de l'installation...")
    
    try:
        # Test import psutil
        import psutil
        print("✅ psutil - OK")
        
        # Test import platform
        import platform
        print("✅ platform - OK")
        
        # Test import subprocess
        import subprocess
        print("✅ subprocess - OK")
        
        # Test spécifique à la plateforme
        system = platform.system()
        if system == "Windows":
            try:
                import wmi
                print("✅ wmi - OK")
            except ImportError:
                print("⚠️  wmi - Non disponible (optionnel)")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur de test: {e}")
        return False

def create_config_file():
    """Crée un fichier de configuration par défaut"""
    config_content = """# Configuration Osiris
# Fichier de configuration par défaut

[general]
# Niveau de log (DEBUG, INFO, WARNING, ERROR)
log_level = INFO

# Dossier de sortie par défaut
output_dir = output

# Timeout des collecteurs (secondes)
timeout = 300

[collectors]
# Collecteurs à exécuter par défaut
default_collectors = users,processes,network

# Collecteurs sensibles (nécessitent des privilèges admin)
sensitive_collectors = services,registry,events

[output]
# Format de sortie (json, csv, xml)
format = json

# Compression des résultats
compress = false

# Horodatage automatique
timestamp = true
"""
    
    try:
        with open("config/osiris.conf", "w", encoding="utf-8") as f:
            f.write(config_content)
        print("✅ Fichier de configuration créé: config/osiris.conf")
    except Exception as e:
        print(f"❌ Erreur création config: {e}")

def main():
    """Fonction principale d'installation"""
    print_banner()
    
    # Vérifications préliminaires
    if not check_python_version():
        sys.exit(1)
    
    platform_name = detect_platform()
    
    # Installation des dépendances
    install_requirements()
    install_platform_specific(platform_name)
    
    # Création de la structure
    create_directories()
    create_config_file()
    
    # Test final
    if test_installation():
        print("\n" + "="*60)
        print("🎉 INSTALLATION TERMINÉE AVEC SUCCÈS !")
        print("="*60)
        print("\n🚀 Osiris est prêt à l'emploi !")
        print("\n📖 Utilisation:")
        print("  python osiris.py --help")
        print("  python osiris.py --system-info")
        print("  python osiris.py --collect users --output scan.json")
        print("  python osiris.py --collect-all --output full_scan.json")
        print("\n💡 Pour une collecte complète, exécutez en tant qu'administrateur")
        print("\n📁 Fichiers créés:")
        print("  • config/osiris.conf - Configuration")
        print("  • output/ - Dossier de sortie")
        print("  • logs/ - Dossier des logs")
        print("\n🔧 Support:")
        print("  • Documentation: README.md")
        print("  • Tests: python test_osiris_simple.py")
        print("  • Logs: osiris.log")
        
        return True
    else:
        print("\n❌ Installation échouée. Consultez les erreurs ci-dessus.")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1) 