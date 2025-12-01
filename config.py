# === API LM Studio ===
LM_STUDIO_API = "http://localhost:1234/v1/chat/completions"
LM_MODEL = "mistral-7b-instruct"  # Nom exact de votre modèle
# === Ports des agents ===
COLLECTOR_PORT = 5001
ANALYZER_PORT = 5002
RESPONDER_PORT = 5003
# === Mode de fonctionnement ===
DRY_RUN = True  # True = simulation, False = blocage réel
BLOCKING_BACKEND = "ufw"  # Options: "ufw" ou "iptables" # === Backend de blocage ===
# === Whitelist (IPs à ne JAMAIS bloquer) ===
WHITELIST_IPS = [
    "127.0.0.1",
    "10.0.0.1",      # Passerelle
    "10.0.0.10",     # Ubuntu SOC lui-même
    # Ajouter l'IP de votre machine hôte si besoin
]
SSH_FAIL_THRESHOLD = 5        # Nombre d'échecs SSH avant alerte
SCAN_RATE_THRESHOLD = 50      # Paquets/sec considérés comme scan
HTTP_404_THRESHOLD = 20       # Nombre de 404 avant alerte fuzzing
# === Chemins des logs ===
LOG_PATHS = {
    "ssh": "/var/log/auth.log",
    "firewall": "/var/log/ufw.log",
    "web": "/var/log/nginx/access.log"
}
# === Fichier de sortie ===
ALERT_LOG_FILE = "/tmp/alerts.log"
# === Webhooks (optionnel) ===
WEBHOOK_URL = None  # Exemple: "http://n8n.local/webhook/soc-alerts"
# === Timeout et retry ===
LM_TIMEOUT = 10  # Timeout requête LM Studio (secondes)
LM_MAX_RETRIES = 2