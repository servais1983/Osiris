# Collecteurs Windows

Ce document décrit les collecteurs Windows disponibles dans Osiris.

## Collecteur de Base (WindowsCollector)

Classe de base pour tous les collecteurs Windows. Fournit des fonctionnalités communes comme :
- Vérification des privilèges
- Récupération des informations système
- Récupération des informations de fichiers

## Collecteur d'Historique de Navigation (BrowserHistoryCollector)

Collecte l'historique de navigation des navigateurs suivants :
- Google Chrome
- Mozilla Firefox
- Microsoft Edge

### Fonctionnalités
- Historique de navigation
- Cookies
- Données de connexion
- Données web

## Collecteur de Journaux d'Événements (WindowsEventLogCollector)

Collecte les journaux d'événements Windows :
- Security
- System
- Application
- Setup
- ForwardedEvents

### Fonctionnalités
- Lecture des événements
- Statistiques des journaux
- Sauvegarde des journaux
- Effacement des journaux

## Collecteur d'Événements (WindowsEventCollector)

Collecte les événements système :
- Événements de sécurité
- Événements système
- Événements d'application

### Fonctionnalités
- Filtrage des événements
- Formatage des messages
- Extraction des données binaires
- Récupération des SID utilisateurs

## Collecteur de Fichiers (WindowsFileCollector)

Collecte les informations sur les fichiers :
- Attributs
- Sécurité
- Métadonnées
- Hachages

### Fonctionnalités
- Scan de répertoires
- Récupération des attributs
- Calcul des hachages
- Détection des types de fichiers

## Collecteur Réseau (WindowsNetworkCollector)

Collecte les informations réseau :
- Connexions TCP/UDP
- Interfaces réseau
- Tables de routage
- Règles de pare-feu

### Fonctionnalités
- État des connexions
- Statistiques réseau
- Configuration DNS
- Table ARP

## Collecteur de Processus (WindowsProcessCollector)

Collecte les informations sur les processus :
- PID
- Utilisation CPU/Mémoire
- Handles
- Modules chargés

### Fonctionnalités
- Statistiques des processus
- Handles ouverts
- Modules chargés
- Variables d'environnement

## Collecteur de Registre (WindowsRegistryCollector)

Collecte les informations du registre Windows :
- Ruches principales
- Clés importantes
- Valeurs
- Sécurité

### Fonctionnalités
- Lecture des valeurs
- Modification des valeurs
- Suppression de clés
- Création de clés

## Collecteur de Services (WindowsServiceCollector)

Collecte les informations sur les services Windows :
- État
- Configuration
- Dépendances
- Sécurité

### Fonctionnalités
- État des services
- Configuration
- Dépendances
- Informations de sécurité

## Collecteur d'Utilisateurs (WindowsUserCollector)

Collecte les informations sur les utilisateurs :
- Profils
- Groupes
- Sessions
- Privilèges

### Fonctionnalités
- Profils utilisateurs
- Groupes
- Sessions actives
- Privilèges

## Utilisation

```python
from collectors.windows import WindowsCollector

# Créer un collecteur
collector = WindowsCollector()

# Collecter les données
data = collector.collect()
```

## Prérequis

- Windows 10 ou supérieur
- Python 3.8 ou supérieur
- Privilèges administrateur
- Bibliothèques requises (voir requirements.txt)

## Dépannage

### Problèmes Courants

1. **Erreur de privilèges**
   - Vérifier que l'application est exécutée en tant qu'administrateur
   - Vérifier les privilèges de l'utilisateur

2. **Erreur d'accès aux fichiers**
   - Vérifier les permissions NTFS
   - Vérifier les politiques de sécurité

3. **Erreur de collecte**
   - Vérifier les logs
   - Vérifier la configuration
   - Vérifier les dépendances

## Contribution

Les contributions sont les bienvenues ! Consultez le guide de contribution pour plus de détails. 