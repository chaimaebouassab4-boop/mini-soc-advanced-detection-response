# responder.py - Exécuteur des actions de sécurité

from flask import Flask, request, jsonify
import subprocess
import json
import datetime
import config

app = Flask(__name__)

def log_alert(decision):
    """Enregistre l'alerte dans le fichier de log"""
    timestamp = datetime.datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "event_id": decision.get("event_id"),
        "severity": decision.get("severity"),
        "category": decision.get("category"),
        "action": decision.get("recommended_action"),
        "target": decision.get("target"),
        "reasoning": decision.get("reasoning", "")
    }
    
    with open(config.ALERT_LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    print(f"[Responder] 📝 Alerte enregistrée : {log_entry['category']} - {log_entry['action']}")


def block_ip(ip_address):
    """Bloque une IP via UFW ou iptables"""
    
    # Vérifier whitelist
    if ip_address in config.WHITELIST_IPS:
        print(f"[Responder] ⚠️ IP {ip_address} en whitelist, blocage annulé")
        return False
    
    if config.DRY_RUN:
        print(f"[Responder] 🧪 [DRY RUN] IP {ip_address} aurait été bloquée")
        return True
    
    try:
        if config.BLOCKING_BACKEND == "ufw":
            cmd = f"sudo ufw deny from {ip_address}"
        elif config.BLOCKING_BACKEND == "iptables":
            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        else:
            print(f"[Responder] ❌ Backend inconnu : {config.BLOCKING_BACKEND}")
            return False
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[Responder] 🛡️ IP {ip_address} BLOQUÉE via {config.BLOCKING_BACKEND}")
            return True
        else:
            print(f"[Responder] ❌ Échec blocage : {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[Responder] ❌ Erreur blocage IP : {e}")
        return False


@app.route('/action', methods=['POST'])
def execute_action():
    """Endpoint pour recevoir les décisions de l'analyzer"""
    
    decision = request.json
    
    print(f"\n[Responder] 📥 Décision reçue : {decision.get('recommended_action')} pour {decision.get('target')}")
    
    # Toujours logger
    log_alert(decision)
    
    # Exécuter l'action
    action = decision.get('recommended_action')
    
    if action == 'log':
        # Déjà fait ci-dessus
        pass
    
    elif action == 'alert':
        print(f"[Responder] 🚨 ALERTE : {decision.get('category')} - Sévérité {decision.get('severity')}")
        # Optionnel : envoyer webhook
        if config.WEBHOOK_URL:
            try:
                requests.post(config.WEBHOOK_URL, json=decision, timeout=5)
            except:
                pass
    
    elif action == 'block_ip':
        target_ip = decision.get('target')
        if target_ip:
            block_ip(target_ip)
        else:
            print(f"[Responder] ⚠️ Pas d'IP cible pour le blocage")
    
    return jsonify({"status": "executed"}), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "responder"}), 200


if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════╗
║    RESPONDER DÉMARRÉ                 ║
║    Port: {config.RESPONDER_PORT}                    ║
║    Mode: {'DRY RUN (simulation)' if config.DRY_RUN else 'PRODUCTION (blocage réel)'}  ║
║    Backend: {config.BLOCKING_BACKEND}                  ║
╚══════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=config.RESPONDER_PORT, debug=False)