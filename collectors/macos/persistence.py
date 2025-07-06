import os
import pwd
import plistlib
from dataclasses import dataclass
from typing import Iterator, List, Optional

@dataclass
class PersistenceEntry:
    path: str
    label: str
    program: Optional[str]
    program_arguments: Optional[List[str]]
    run_at_load: bool
    type: str  # "Agent" ou "Daemon"

class MacPersistenceCollector:
    """
    Collecte les artefacts de persistance macOS (LaunchAgents/Daemons).
    """
    PERSISTENCE_PATHS = {
        "/System/Library/LaunchAgents": "System Agent",
        "/Library/LaunchAgents": "Global Agent",
        "/Library/LaunchDaemons": "Global Daemon",
        "~/Library/LaunchAgents": "User Agent",
    }

    def _parse_plist(self, file_path: str, entry_type: str) -> Optional[PersistenceEntry]:
        try:
            with open(file_path, "rb") as f:
                plist_data = plistlib.load(f)
            label = plist_data.get("Label")
            program_args = plist_data.get("ProgramArguments")
            program = plist_data.get("Program")
            run_at_load = plist_data.get("RunAtLoad", False)
            prog = program
            if program_args:
                prog = program_args[0] if isinstance(program_args, list) and program_args else None
            if not label or not (program or program_args):
                return None
            return PersistenceEntry(
                path=file_path,
                label=label,
                program=prog,
                program_arguments=program_args,
                run_at_load=run_at_load,
                type=entry_type,
            )
        except (plistlib.InvalidFileException, PermissionError, ValueError):
            return None

    def collect(self) -> Iterator[PersistenceEntry]:
        # Chemins globaux
        for path, entry_type in self.PERSISTENCE_PATHS.items():
            if not path.startswith("~"):
                if not os.path.isdir(path):
                    continue
                for filename in os.listdir(path):
                    if filename.endswith(".plist"):
                        full_path = os.path.join(path, filename)
                        entry = self._parse_plist(full_path, entry_type)
                        if entry:
                            yield entry
        # Chemins utilisateurs
        user_agent_path_template = self.PERSISTENCE_PATHS.get("~/Library/LaunchAgents")
        if user_agent_path_template:
            for user_info in pwd.getpwall():
                home_dir = user_info.pw_dir
                user_path = os.path.expanduser(os.path.join(home_dir, "Library/LaunchAgents"))
                if not os.path.isdir(user_path):
                    continue
                for filename in os.listdir(user_path):
                    if filename.endswith(".plist"):
                        full_path = os.path.join(user_path, filename)
                        entry = self._parse_plist(full_path, "User Agent")
                        if entry:
                            yield entry

if __name__ == "__main__":
    collector = MacPersistenceCollector()
    for item in collector.collect():
        print(
            f"Type: {item.type}, Label: {item.label}, "
            f"Program: {item.program}, RunAtLoad: {item.run_at_load}"
        ) 