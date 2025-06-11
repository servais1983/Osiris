# Arrêt des services Docker
docker-compose down

# Arrêt des processus Python
Get-Process | Where-Object { $_.CommandLine -like "*hive/web_server.py*" -or $_.CommandLine -like "*hive/hive.py*" } | Stop-Process -Force

Write-Host "Osiris est arrêté !" 