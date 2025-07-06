import os
import re
from dataclasses import dataclass
from typing import Iterator, Optional

# Définition de la structure pour une entrée de log parsée.
@dataclass
class AuthLogEntry:
    timestamp: str
    hostname: str
    process_name: str
    pid: Optional[int]
    message: str
    raw_line: str

class AuthLogCollector:
    """
    Collecte et parse les logs d'authentification Linux (auth.log, secure).
    """
    # Chemins possibles pour les logs d'authentification
    LOG_FILES = ["/var/log/auth.log", "/var/log/secure"]

    # Expression régulière pour parser une ligne de syslog standard.
    LOG_REGEX = re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process_name>[a-zA-Z0-9\._-]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )

    def collect(self) -> Iterator[AuthLogEntry]:
        """
        Trouve le bon fichier de log et stream son contenu parsé.
        """
        target_file = None
        for log_file in self.LOG_FILES:
            if os.path.exists(log_file):
                target_file = log_file
                break

        if not target_file:
            # Aucun fichier de log trouvé
            return

        try:
            with open(target_file, "r", errors="ignore") as f:
                for line in f:
                    match = self.LOG_REGEX.match(line)
                    if match:
                        data = match.groupdict()
                        pid = data.get("pid")
                        yield AuthLogEntry(
                            timestamp=data["timestamp"],
                            hostname=data["hostname"],
                            process_name=data["process_name"],
                            pid=int(pid) if pid else None,
                            message=data["message"].strip(),
                            raw_line=line.strip()
                        )
        except (IOError, OSError) as e:
            print(f"Could not read {target_file}: {e}")

# Pour tester le collecteur directement
if __name__ == '__main__':
    collector = AuthLogCollector()
    for entry in collector.collect():
        print(f"[{entry.timestamp}] Process: {entry.process_name}, Message: {entry.message}") 