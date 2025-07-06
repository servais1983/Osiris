import subprocess
import json
from dataclasses import dataclass, fields
from typing import Iterator, Optional
import os

@dataclass
class UnifiedLogEntry:
    timestamp: str
    processImagePath: Optional[str]
    senderImagePath: Optional[str]
    subsystem: Optional[str]
    category: Optional[str]
    eventType: Optional[str]
    traceID: Optional[str]
    processID: int
    threadID: int
    message: str

class MacUnifiedLogsCollector:
    """
    Collecte les Unified Logs macOS via la commande 'log show'.
    """
    def collect(self, predicate: Optional[str] = None) -> Iterator[UnifiedLogEntry]:
        command = ["log", "show", "--style", "json"]
        if predicate:
            command.extend(["--predicate", predicate])
        else:
            command.extend(["--last", "1h"])
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if process.stdout is None:
                return
            for line in process.stdout:
                try:
                    log_data = json.loads(line)
                    field_names = {f.name for f in fields(UnifiedLogEntry)}
                    filtered_data = {k: v for k, v in log_data.items() if k in field_names}
                    if "eventMessage" in log_data:
                        filtered_data["message"] = log_data["eventMessage"]
                    else:
                        continue
                    yield UnifiedLogEntry(**filtered_data)
                except (json.JSONDecodeError, TypeError):
                    continue
            stderr = process.stderr.read()
            if stderr:
                print(f"Error while running log command: {stderr}")
        except FileNotFoundError:
            print("Command 'log' not found. Is this a macOS system?")
        except Exception as e:
            print(f"An error occurred while collecting unified logs: {e}")

if __name__ == "__main__":
    collector = MacUnifiedLogsCollector()
    print("Collecting last 5 Unified Log entries...")
    count = 0
    for entry in collector.collect():
        if count < 5:
            print(
                f"[{entry.timestamp}] "
                f"Process: {os.path.basename(entry.processImagePath) if entry.processImagePath else 'N/A'}, "
                f"Message: {entry.message}"
            )
            count += 1
        else:
            break 