# Activation de l'environnement virtuel
.\.venv\Scripts\Activate.ps1

# Démarrage des services avec Docker Compose
docker compose up -d

# Attente que les services soient prêts
Write-Host "Attente du démarrage des services..."
Start-Sleep -Seconds 10

# Démarrage du serveur web
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $PWD; .\.venv\Scripts\activate; python hive/web_server.py"

# Démarrage du serveur Hive
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $PWD; .\.venv\Scripts\activate; python hive/hive.py"

Write-Host "Osiris est démarré !"
Write-Host "Interface web : http://localhost:8002"
Write-Host "Serveur Hive : localhost:50051" 