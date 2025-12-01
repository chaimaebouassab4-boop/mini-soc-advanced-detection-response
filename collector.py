# collector.py - Point d'entrée des événements
from flask import Flask, request, jsonify
import requests
import config
app = Flask(__name__)
@app.route('/event', methods=['POST'])
def receive_event():
    """Reçoit un événement et le forwarde à l'analyzer"""
    event = request.json
    print(f"[Collector] 📨 Événement reçu : {event.get('kind')} depuis {event.get('src_ip')}")
    try:
        response = requests.post(  # Forward vers l'analyzer
            f"http://localhost:{config.ANALYZER_PORT}/analyze",
            json=event,
            timeout=15  # Timeout plus long (inclut temps IA)
        )
        if response.status_code == 200:
            print(f"[Collector] ✅ Événement transmis à l'analyzer")
            return jsonify({"status": "forwarded"}), 200
        else:
            print(f"[Collector] ⚠️ Analyzer a retourné : {response.status_code}")
            return jsonify({"status": "error"}), 500  
    except requests.exceptions.Timeout:
        print(f"[Collector] ⏱️ Timeout lors de l'envoi à l'analyzer")
        return jsonify({"status": "timeout"}), 504
    except Exception as e:
        print(f"[Collector] ❌ Erreur : {e}")
        return jsonify({"status": "error"}), 500
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "collector"}), 200
if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════╗
║    COLLECTOR DÉMARRÉ                 ║
║    Port: {config.COLLECTOR_PORT}                    ║
║    Prêt à recevoir événements        ║
╚══════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=config.COLLECTOR_PORT, debug=False)