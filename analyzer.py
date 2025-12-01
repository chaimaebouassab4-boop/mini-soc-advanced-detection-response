# analyzer.py - Cerveau du SOC (heuristiques + IA)

from flask import Flask, request, jsonify
import requests
import json
import datetime
from collections import defaultdict
import config
import lm_client

app = Flask(__name__)

# Stockage temporaire pour corrélation
event_history = defaultdict(list)  # {src_ip: [timestamps]}

def apply_heuristics(event):
    """
    Applique des règles heuristiques simples
    
    Returns:
        dict: Décision basée sur heuristiques ou None
    """
    
    kind = event.get('kind')
    src_ip = event.get('src_ip')
    
    # Règle 1 : SSH Failed - Compter les échecs récents
    if kind == 'ssh_failed':
        event_history[src_ip].append(datetime.datetime.now())
        
        # Garder seulement les événements des 5 dernières minutes
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=5)
        event_history[src_ip] = [ts for ts in event_history[src_ip] if ts > cutoff]
        
        fail_count = len(event_history[src_ip])
        
        print(f"[Analyzer] 🔍 Heuristique SSH : {fail_count} échecs depuis {src_ip}")
        
        if fail_count >= config.SSH_FAIL_THRESHOLD:
            return {
                "severity": "high",
                "category": "bruteforce",
                "recommended_action": "block_ip",
                "reasoning": f"{fail_count} échecs SSH en 5 min",
                "source": "heuristic"
            }
    
    # Règle 2 : Scan détecté (simple pattern matching)
    if kind == 'firewall_block' and 'SYN' in event.get('raw', ''):
        return {
            "severity": "medium",
            "category": "scan",
            "recommended_action": "alert",
            "reasoning": "Pattern de scan TCP détecté",
            "source": "heuristic"
        }
    
    # Règle 3 : Web fuzzing (nombreuses 404)
    if kind == 'http_404':
        event_history[f"http_{src_ip}"].append(datetime.datetime.now())
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=2)
        event_history[f"http_{src_ip}"] = [ts for ts in event_history[f"http_{src_ip}"] if ts > cutoff]
        
        count_404 = len(event_history[f"http_{src_ip}"])
        
        if count_404 >= config.HTTP_404_THRESHOLD:
            return {
                "severity": "medium",
                "category": "web_fuzzing",
                "recommended_action": "block_ip",
                "reasoning": f"{count_404} requêtes 404 en 2 min",
                "source": "heuristic"
            }
    
    return None  # Pas de décision heuristique


def merge_decisions(heuristic_decision, ai_decision):
    """
    Fusionne les décisions heuristique et IA
    Priorité : heuristique > IA (pour la sécurité)
    """
    
    if heuristic_decision and ai_decision:
        # Prendre la sévérité la plus haute
        severities = ['low', 'medium', 'high', 'critical']
        h_sev = severities.index(heuristic_decision.get('severity', 'low'))
        ai_sev = severities.index(ai_decision.get('severity', 'low'))
        final_severity = severities[max(h_sev, ai_sev)]
        
        # Prendre l'action la plus restrictive
        actions = ['log', 'alert', 'block_ip']
        h_act = actions.index(heuristic_decision.get('recommended_action', 'log'))
        ai_act = actions.index(ai_decision.get('recommended_action', 'log'))
        final_action = actions[max(h_act, ai_act)]
        
        return {
            "severity": final_severity,
            "category": heuristic_decision.get('category'),
            "recommended_action": final_action,
            "reasoning": f"Heuristique: {heuristic_decision.get('reasoning')} | IA: {ai_decision.get('reasoning')}",
            "source": "hybrid"
        }
    
    elif heuristic_decision:
        return heuristic_decision
    
    elif ai_decision:
        return ai_decision
    
    else:
        # Décision par défaut
        return {
            "severity": "low",
            "category": "unknown",
            "recommended_action": "log",
            "reasoning": "Pas de décision claire",
            "source": "default"
        }


@app.route('/analyze', methods=['POST'])
def analyze_event():
    """Endpoint pour recevoir et analyser un événement"""
    
    event = request.json
    
    print(f"\n[Analyzer] 📊 Analyse événement : {event.get('kind')} depuis {event.get('src_ip')}")
    
    # Phase 1 : Heuristiques
    heuristic_decision = apply_heuristics(event)
    
    # Phase 2 : Analyse IA
    ai_decision = lm_client.query_lm_studio(event)
    
    # Phase 3 : Fusion
    final_decision = merge_decisions(heuristic_decision, ai_decision)
    
    # Enrichir avec métadonnées
    final_decision['event_id'] = event.get('id')
    final_decision['target'] = event.get('src_ip')
    final_decision['timestamp'] = datetime.datetime.now().isoformat()
    
    print(f"[Analyzer] ✅ Décision finale : {final_decision['recommended_action']} (source: {final_decision['source']})")
    
    # Envoyer au Responder
    try:
        requests.post(
            f"http://localhost:{config.RESPONDER_PORT}/action",
            json=final_decision,
            timeout=5
        )
    except Exception as e:
        print(f"[Analyzer] ⚠️ Erreur envoi au Responder : {e}")
    
    return jsonify(final_decision), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "analyzer"}), 200


if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════╗
║    ANALYZER DÉMARRÉ                  ║
║    Port: {config.ANALYZER_PORT}                    ║
║    LM Studio: {'✅ Activé' if config.LM_STUDIO_API else '❌ Désactivé'} ║
╚══════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=config.ANALYZER_PORT, debug=False)