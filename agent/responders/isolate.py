import platform
import subprocess
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class IsolateHostResponder:
    def __init__(self, hive_ip: str, hive_port: int):
        """
        Initialise le responder avec les informations du serveur Hive
        pour ne pas couper la communication avec lui.
        """
        self.hive_ip = hive_ip
        self.hive_port = hive_port
        self.os_name = platform.system()
        self.isolation_applied = False

    def _run_command(self, command: list) -> Tuple[bool, str]:
        """Exécute une commande système et gère les erreurs."""
        try:
            logger.info(f"Executing command: {' '.join(command)}")
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: {' '.join(command)}, Error: {e.stderr}"
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = f"Command not found: {command[0]}"
            logger.error(error_msg)
            return False, error_msg

    def isolate(self) -> Tuple[bool, str]:
        """Applique les règles de pare-feu pour isoler l'hôte."""
        logger.info(f"Applying network isolation, allowing traffic to {self.hive_ip}:{self.hive_port}")
        
        if self.os_name == "Linux":
            return self._isolate_linux()
        elif self.os_name == "Windows":
            return self._isolate_windows()
        elif self.os_name == "Darwin":
            return self._isolate_macos()
        else:
            error_msg = f"Unsupported OS: {self.os_name}"
            logger.error(error_msg)
            return False, error_msg

    def _isolate_linux(self) -> Tuple[bool, str]:
        """Isole l'hôte sur Linux en utilisant iptables."""
        try:
            # Sauvegarder les règles actuelles
            self._run_command(["iptables-save", "-f", "/tmp/iptables_backup.rules"])
            
            # Appliquer les règles d'isolement
            commands = [
                ["iptables", "-P", "INPUT", "DROP"],
                ["iptables", "-P", "OUTPUT", "DROP"],
                ["iptables", "-P", "FORWARD", "DROP"],
                ["iptables", "-A", "OUTPUT", "-d", self.hive_ip, "-p", "tcp", "--dport", str(self.hive_port), "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-s", self.hive_ip, "-p", "tcp", "--sport", str(self.hive_port), "-j", "ACCEPT"],
                # Permettre le trafic local
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ]
            
            for cmd in commands:
                success, error = self._run_command(cmd)
                if not success:
                    return False, f"Failed command '{' '.join(cmd)}': {error}"
            
            self.isolation_applied = True
            return True, "Host isolated successfully using iptables."
            
        except Exception as e:
            return False, f"Linux isolation failed: {str(e)}"

    def _isolate_windows(self) -> Tuple[bool, str]:
        """Isole l'hôte sur Windows en utilisant Windows Firewall."""
        try:
            # Créer une règle pour bloquer tout le trafic sortant
            block_outgoing = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Osiris_Block_All_Outgoing",
                "dir=out", "action=block", "enable=yes"
            ]
            
            # Créer une règle pour bloquer tout le trafic entrant
            block_incoming = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Osiris_Block_All_Incoming",
                "dir=in", "action=block", "enable=yes"
            ]
            
            # Créer une règle pour permettre le trafic vers le Hive
            allow_hive = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Osiris_Allow_Hive",
                "dir=out", "action=allow", "enable=yes",
                f"remoteip={self.hive_ip}", f"remoteport={self.hive_port}"
            ]
            
            commands = [block_outgoing, block_incoming, allow_hive]
            
            for cmd in commands:
                success, error = self._run_command(cmd)
                if not success:
                    return False, f"Failed command '{' '.join(cmd)}': {error}"
            
            self.isolation_applied = True
            return True, "Host isolated successfully using Windows Firewall."
            
        except Exception as e:
            return False, f"Windows isolation failed: {str(e)}"

    def _isolate_macos(self) -> Tuple[bool, str]:
        """Isole l'hôte sur macOS en utilisant pf (Packet Filter)."""
        try:
            # Créer un fichier de règles pf temporaire
            pf_rules = f"""
# Règles d'isolement Osiris
set skip on lo

# Bloquer tout le trafic par défaut
block drop all

# Permettre le trafic vers le Hive
pass out proto tcp to {self.hive_ip} port {self.hive_port}
pass in proto tcp from {self.hive_ip} port {self.hive_port}
"""
            
            # Écrire les règles dans un fichier temporaire
            with open("/tmp/osiris_isolation.conf", "w") as f:
                f.write(pf_rules)
            
            # Charger les règles
            success, error = self._run_command(["pfctl", "-f", "/tmp/osiris_isolation.conf"])
            if not success:
                return False, f"Failed to load pf rules: {error}"
            
            # Activer pf
            success, error = self._run_command(["pfctl", "-e"])
            if not success:
                return False, f"Failed to enable pf: {error}"
            
            self.isolation_applied = True
            return True, "Host isolated successfully using pf."
            
        except Exception as e:
            return False, f"macOS isolation failed: {str(e)}"

    def deisolate(self) -> Tuple[bool, str]:
        """Supprime les règles de pare-feu pour restaurer la connectivité."""
        logger.info("Removing network isolation")
        
        if not self.isolation_applied:
            return True, "No isolation was applied."
        
        if self.os_name == "Linux":
            return self._deisolate_linux()
        elif self.os_name == "Windows":
            return self._deisolate_windows()
        elif self.os_name == "Darwin":
            return self._deisolate_macos()
        else:
            return False, f"Unsupported OS: {self.os_name}"

    def _deisolate_linux(self) -> Tuple[bool, str]:
        """Restaure la connectivité sur Linux."""
        try:
            # Restaurer les règles sauvegardées
            success, error = self._run_command(["iptables-restore", "/tmp/iptables_backup.rules"])
            if not success:
                # Fallback: réinitialiser iptables
                self._run_command(["iptables", "-F"])
                self._run_command(["iptables", "-P", "INPUT", "ACCEPT"])
                self._run_command(["iptables", "-P", "OUTPUT", "ACCEPT"])
                self._run_command(["iptables", "-P", "FORWARD", "ACCEPT"])
            
            self.isolation_applied = False
            return True, "Linux isolation removed successfully."
            
        except Exception as e:
            return False, f"Linux deisolation failed: {str(e)}"

    def _deisolate_windows(self) -> Tuple[bool, str]:
        """Restaure la connectivité sur Windows."""
        try:
            # Supprimer les règles créées
            commands = [
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Osiris_Block_All_Outgoing"],
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Osiris_Block_All_Incoming"],
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Osiris_Allow_Hive"]
            ]
            
            for cmd in commands:
                self._run_command(cmd)  # On ignore les erreurs car les règles peuvent ne pas exister
            
            self.isolation_applied = False
            return True, "Windows isolation removed successfully."
            
        except Exception as e:
            return False, f"Windows deisolation failed: {str(e)}"

    def _deisolate_macos(self) -> Tuple[bool, str]:
        """Restaure la connectivité sur macOS."""
        try:
            # Désactiver pf
            self._run_command(["pfctl", "-d"])
            
            # Supprimer le fichier de règles
            self._run_command(["rm", "-f", "/tmp/osiris_isolation.conf"])
            
            self.isolation_applied = False
            return True, "macOS isolation removed successfully."
            
        except Exception as e:
            return False, f"macOS deisolation failed: {str(e)}"

    def get_status(self) -> dict:
        """Retourne le statut actuel de l'isolation."""
        return {
            "os": self.os_name,
            "hive_ip": self.hive_ip,
            "hive_port": self.hive_port,
            "isolation_applied": self.isolation_applied
        } 