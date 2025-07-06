from .slack import SlackNotifier
from .email_notifier import EmailNotifier

class NotificationDispatcher:
    def __init__(self, config):
        """Initialise les notifiers disponibles en fonction de la config."""
        self.notifiers = []
        if config.get("slack", {}).get("enabled"):
            self.notifiers.append(SlackNotifier(config["slack"]))
        if config.get("email", {}).get("enabled"):
            self.notifiers.append(EmailNotifier(config["email"]))

    def dispatch(self, alert_data):
        """Envoie une alerte à tous les notifiers configurés."""
        print(f"Dispatching alert '{alert_data['title']}'...")
        for notifier in self.notifiers:
            notifier.send(alert_data)

# Exemple de Notifier (à mettre dans son propre fichier, ex: slack.py)
class SlackNotifier:
    def __init__(self, slack_config):
        self.webhook_url = slack_config["webhook_url"]
    
    def send(self, alert_data):
        # Logique pour formater le message et l'envoyer au webhook Slack
        message = f"🚨 *Osiris Alert: {alert_data['title']}*\n> Severity: {alert_data['severity']}\n> Agent: {alert_data['agent_name']}"
        # requests.post(self.webhook_url, json={"text": message})
        print(f"  -> Sent to Slack: {message}")

class EmailNotifier:
    def __init__(self, email_config):
        self.smtp_server = email_config["smtp_server"]
        self.smtp_port = email_config["smtp_port"]
        self.username = email_config["username"]
        self.password = email_config["password"]
        self.recipients = email_config["recipients"]
    
    def send(self, alert_data):
        # Logique pour envoyer un email
        subject = f"Osiris Alert: {alert_data['title']}"
        body = f"""
        Severity: {alert_data['severity']}
        Agent: {alert_data['agent_name']}
        Details: {alert_data.get('details', 'N/A')}
        """
        # smtplib.sendmail(...)
        print(f"  -> Sent email: {subject}") 