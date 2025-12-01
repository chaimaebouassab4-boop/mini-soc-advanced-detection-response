# log_tailer.py - Observateur de logs système
import time
import re
import json
import datetime
import requests
import subprocess
import config
def tail_file(filepath):
    """Générateur qui lit un fichier en continu (comme tail -f)"""
    try:
        with open(filepath, 'r') as f:
            # Se positionner à la fin du fichier
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    yield line.strip()
                else:
                    time.sleep(0.1)
    except FileNotFoundError:
        print(f"[Tailer] ⚠️ Fichier non trouvé : {filepath}")
    except PermissionError:
        print(f"[Tailer] ❌ Permission refusée : {filepath} (exécuter avec sudo)")
def parse_ssh_log(line):
    """Parse une ligne de /var/log/auth.log"""
    # Pattern : Failed password for USER from IP port PORT
    pattern = r'Failed password for (\w+) from ([\d\.]+) port (\d+)'
    match = re.search(pattern, line)
    if match:
        return {
            "id": f"ssh-{int(time.time() * 1000)}",
            "ts": datetime.datetime.now().isoformat(),
            "kind": "ssh_failed",
            "src_ip": match.group(2),
            "dst": "ubuntu-soc",
            "user": match.group(1),
            "raw": line
        }
    return None
def parse_ufw_log(line):
    """Parse une ligne de /var/log/ufw.log"""
    # Pattern UFW : [UFW BLOCK] ... SRC=IP
    if '[UFW BLOCK]' in line or '[UFW AUDIT]' in line:
        src_match = re.search(r'SRC=([\d\.]+)', line)
        dst_match = re.search(r'DST=([\d\.]+)', line)
        
        if src_match:
            return {
                "id": f"fw-{int(time.time() * 1000)}",
                "ts": datetime.datetime.now().isoformat(),
                "kind": "firewall_block",
                "src_ip": src_match.group(1),
                "dst": dst_match.group(1) if dst_match else "unknown",
                "raw": line
            }
    return None
def parse_nginx_log(line):
    """Parse une ligne de /var/log/nginx/access.log"""
    # Pattern nginx : IP - - [date] "METHOD /path HTTP/1.1" STATUS SIZE
    pattern = r'^([\d\.]+) .* "(\w+) ([^ ]+) HTTP/[\d\.]+" (\d+)'
    match = re.search(pattern, line)
    if match:
        ip, method, path, status = match.groups()
        
        # Détecter 404 (fuzzing potentiel)
        if status == '404':
            return {
                "id": f"http-{int(time.time() * 1000)}",
                "ts": datetime.datetime.now().isoformat(),
                "kind": "http_404",
                "src_ip": ip,
                "method": method,
                "path": path,
                "raw": line
            }
    return None
def send_event(event):
    """Envoie un événement au collector"""
    try:
        response = requests.post(
            f"http://localhost:{config.COLLECTOR_PORT}/event",
            json=event,
            timeout=5
        )
        if response.status_code == 200:
            print(f"[Tailer] ✅ Événement envoyé : {event['kind']} depuis {event['src_ip']}")
        else:
            print(f"[Tailer] ⚠️ Échec envoi : {response.status_code}")
    except Exception as e:
        print(f"[Tailer] ❌ Erreur envoi : {e}")
def monitor_logs():
    """Monitore les 3 sources de logs en parallèle"""
    
    print("""
╔══════════════════════════════════════╗
║    LOG TAILER DÉMARRÉ                ║
║    Monitoring :                      ║
║    - /var/log/auth.log (SSH)        ║
║    - /var/log/ufw.log (Firewall)    ║
║    - /var/log/nginx/access.log (Web)║
╚══════════════════════════════════════╝
    """)
    # Dans un vrai système, on utiliserait des threads
    # Ici version simplifiée : un seul fichier à la fois
    import sys
    if len(sys.argv) > 1:
        log_type = sys.argv[1]
    else:
        log_type = "ssh"  # Par défaut
    
    if log_type == "ssh":
        filepath = config.LOG_PATHS["ssh"]
        parser = parse_ssh_log
    elif log_type == "firewall":
        filepath = config.LOG_PATHS["firewall"]
        parser = parse_ufw_log
    elif log_type == "web":
        filepath = config.LOG_PATHS["web"]
        parser = parse_nginx_log
    else:
        print(f"[Tailer] ❌ Type inconnu : {log_type}")
    for line in tail_file(filepath):
        event = parser(line)
        if event:
            send_event(event)


if __name__ == "__main__":
    monitor_logs()