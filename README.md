# 🏺 Osiris - Plateforme DFIR de Nouvelle Génération

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-En%20Développement-orange.svg)

## 📋 Description

Osiris est une plateforme unifiée de Réponse à Incidents et d'Investigation Numérique (DFIR) qui combine les meilleures fonctionnalités des outils existants dans un écosystème cohérent et intelligent. La plateforme intègre la puissance de collecte de Velociraptor, les capacités de parsing de KAPE, et l'analyse approfondie d'Autopsy, le tout enrichi par une couche d'intelligence artificielle.

## ✨ Fonctionnalités Principales

### 🏗️ Architecture Hybride et Distribuée
- **Osiris Hive** : Serveur central déployable on-premise ou cloud
- **Osiris Agents** : Agents légers multi-plateformes (Windows, Linux, macOS)
- Communication sécurisée via gRPC sur TLS mutuel

### 🔍 Collecte Puissante via OQL
- **Osiris Query Language (OQL)** : Langage de requêtes unifié
- **Recettes de Collecte** : Bibliothèque modulaire d'artefacts forensiques
- Support des artefacts courants (Prefetch, Amcache, Shellbags, etc.)

### 🔄 Pipeline d'Analyse Automatisé
- Parsing automatisé des artefacts
- Normalisation des données (ECS)
- Enrichissement :
  - Threat Intelligence
  - Géolocalisation
  - Contexte Interne
- Moteurs de détection :
  - Règles Sigma
  - Règles YARA

### 🤖 Assistance par IA
- Détection d'anomalies
- Résumé d'incidents
- Assistance à l'investigation
- Traducteur OQL (langage naturel vers OQL)

### 🌐 Interface Web Moderne
- Tableau de bord global
- Gestion des agents
- Console de hunting OQL
- Timeline interactive
- Visualisations avancées
- Gestion de cas

## 🛠️ Stack Technologique

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| Backend | Python (FastAPI) / Go | Performance, asynchronisme |
| Base de Données | PostgreSQL + ClickHouse | Optimisé pour l'analytique |
| Frontend | React / TypeScript | Interface moderne et réactive |
| Communication | gRPC / Protobuf | Performance et efficacité |
| Agents | Python / Go | Multi-plateforme, léger |

## 📚 Exemples d'Utilisation

### Collecte de Données Windows

```python
from collectors.windows import (
    WindowsCollector,
    BrowserHistoryCollector,
    WindowsEventLogCollector,
    WindowsFileCollector,
    WindowsNetworkCollector,
    WindowsProcessCollector,
    WindowsRegistryCollector,
    WindowsServiceCollector,
    WindowsUserCollector
)

# Collecte d'historique de navigation
browser_collector = BrowserHistoryCollector()
browser_data = browser_collector.collect()
print(f"Historique de navigation collecté : {len(browser_data['history'])} entrées")

# Collecte de journaux d'événements
event_collector = WindowsEventLogCollector()
event_data = event_collector.collect()
print(f"Événements collectés : {len(event_data['events'])} entrées")

# Collecte de fichiers
file_collector = WindowsFileCollector()
file_data = file_collector.collect()
print(f"Fichiers analysés : {len(file_data['files'])} entrées")

# Collecte réseau
network_collector = WindowsNetworkCollector()
network_data = network_collector.collect()
print(f"Connexions réseau : {len(network_data['connections'])} entrées")

# Collecte de processus
process_collector = WindowsProcessCollector()
process_data = process_collector.collect()
print(f"Processus en cours : {len(process_data['processes'])} entrées")

# Collecte du registre
registry_collector = WindowsRegistryCollector()
registry_data = registry_collector.collect()
print(f"Clés de registre analysées : {len(registry_data['keys'])} entrées")

# Collecte de services
service_collector = WindowsServiceCollector()
service_data = service_collector.collect()
print(f"Services analysés : {len(service_data['services'])} entrées")

# Collecte d'utilisateurs
user_collector = WindowsUserCollector()
user_data = user_collector.collect()
print(f"Utilisateurs analysés : {len(user_data['users'])} entrées")
```

### Utilisation de l'API

```python
import grpc
from osiris_pb2 import CollectRequest
from osiris_pb2_grpc import OsirisStub

# Connexion au serveur
channel = grpc.secure_channel(
    'hive.example.com:443',
    grpc.ssl_channel_credentials()
)
stub = OsirisStub(channel)

# Collecte de données
request = CollectRequest(
    target="windows",
    collectors=["browser_history", "event_logs", "files"],
    options={
        "browser_history": {"browsers": ["chrome", "firefox", "edge"]},
        "event_logs": {"logs": ["security", "system", "application"]},
        "files": {"paths": ["C:\\Windows\\System32", "C:\\Program Files"]}
    }
)

response = stub.Collect(request)
print(f"Données collectées : {response.data}")
```

### Utilisation de l'Interface Web

1. Accédez à l'interface web : `https://hive.example.com`
2. Connectez-vous avec vos identifiants
3. Sélectionnez un agent dans la liste
4. Choisissez les collecteurs à utiliser
5. Configurez les options de collecte
6. Lancez la collecte
7. Visualisez les résultats dans le tableau de bord

## 🗺️ Roadmap

### Phase 1 : Le Cœur ✅
- [x] Agent de base (collecte simple)
- [x] Serveur Hive avec gRPC
- [x] Implémentation OQL

### Phase 2 : Intelligence de Collecte ✅
- [x] Enrichissement OQL
- [x] Bibliothèque de Recettes
- [x] Pipeline de parsing

### Phase 3 : Interface et Analyse ✅
- [x] Interface web React
- [x] Timeline unifiée
- [x] Moteurs Sigma/YARA

### Phase 4 : IA ✅
- [x] Enrichissement TI
- [x] Détection d'anomalies
- [x] Assistance IA

### Phase 5 : Améliorations et Optimisations ✅
- [x] Optimisation des performances
- [x] Tests automatisés
- [x] Documentation complète
- [x] Support multi-langues
- [x] Intégration continue

### Phase 6 : Évolution Future 🚧
- [ ] Support de nouvelles plateformes (macOS, Linux)
- [ ] Intégration avec d'autres outils DFIR (Velociraptor, KAPE)
- [ ] Amélioration des capacités d'IA (analyse comportementale)
- [ ] API publique pour les développeurs
- [ ] Marketplace de plugins et recettes OQL
- [ ] Support des environnements cloud (AWS, Azure, GCP)

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/votre-org/osiris.git

# Accéder au répertoire
cd osiris

# Méthode recommandée : Utiliser Docker Compose
docker-compose up -d

# Alternative : Installation manuelle
pip install -r requirements.txt
```

## 💻 Utilisation

```bash
# Avec Docker Compose (recommandé)
# Le serveur Hive et les services associés sont déjà démarrés
# Accédez à l'interface web : https://localhost:8443

# Installation manuelle
# Démarrer le serveur Hive
python osiris_hive.py

# Démarrer un agent
python osiris_agent.py --server https://hive.example.com
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez notre [guide de contribution](CONTRIBUTING.md) pour plus de détails.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👥 Auteurs

- **Votre Nom** - *Travail initial* - [GitHub](https://github.com/votre-username)

## 🙏 Remerciements

- La communauté DFIR pour son inspiration
- Les projets open source qui ont inspiré Osiris
- Tous les contributeurs

## 📞 Support

Pour toute question ou problème :
- Ouvrir une issue sur GitHub
- Consulter la [documentation](docs/)
- Rejoindre notre [Discord](https://discord.gg/osiris)

## ⚠️ Configuration en Production

Pour une utilisation en production, veuillez consulter la [documentation de configuration](docs/configuration.md) pour :
- Configurer correctement les certificats TLS
- Définir des identifiants sécurisés
- Configurer les bases de données
- Optimiser les performances