# lm_client.py - Client pour communiquer avec LM Studio

import requests
import json
import config

def query_lm_studio(event_data):
    """
    Envoie un événement à LM Studio et retourne l'analyse JSON
    
    Args:
        event_data (dict): Événement structuré
        
    Returns:
        dict: Décision de l'IA ou None en cas d'erreur
    """
    
    # Construction du prompt système
    system_prompt = """Tu es un analyste SOC expert. Ton rôle est d'analyser des événements de sécurité et de recommander des actions.

IMPORTANT : Tu dois TOUJOURS répondre en JSON strict, sans texte avant ou après.

Format de réponse OBLIGATOIRE :
{
  "severity": "low|medium|high|critical",
  "category": "bruteforce|scan|exploit|anomaly|normal",
  "recommended_action": "log|alert|block_ip",
  "reasoning": "Explication courte (max 100 caractères)"
}

Règles de classification :
- bruteforce : tentatives répétées d'authentification
- scan : reconnaissance réseau (nmap, masscan)
- exploit : tentative d'exploitation de vulnérabilité
- anomaly : comportement inhabituel
- normal : activité légitime

Actions :
- log : événement bénin, juste enregistrer
- alert : événement suspect, notifier analyste
- block_ip : menace confirmée, bloquer immédiatement
"""

    # Construction du prompt utilisateur
    user_prompt = f"""Analyse cet événement de sécurité :

Type : {event_data.get('kind', 'unknown')}
IP source : {event_data.get('src_ip', 'unknown')}
Timestamp : {event_data.get('ts', 'unknown')}
Log brut : {event_data.get('raw', 'no raw data')[:200]}

Réponds en JSON strict."""

    # Payload de la requête
    payload = {
        "model": config.LM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,  # Réponses déterministes
        "max_tokens": 200,
        "stream": False
    }

    try:
        # Requête POST vers LM Studio
        response = requests.post(
            config.LM_STUDIO_API,
            json=payload,
            timeout=config.LM_TIMEOUT
        )
        
        response.raise_for_status()  # Lève exception si erreur HTTP
        
        # Extraction de la réponse
        data = response.json()
        ai_response = data['choices'][0]['message']['content']
        
        # Nettoyage (au cas où le LLM ajoute des backticks)
        ai_response = ai_response.strip()
        if ai_response.startswith("```json"):
            ai_response = ai_response[7:]
        if ai_response.startswith("```"):
            ai_response = ai_response[3:]
        if ai_response.endswith("```"):
            ai_response = ai_response[:-3]
        ai_response = ai_response.strip()
        
        # Parsing JSON
        decision = json.loads(ai_response)
        
        print(f"[LM Client] ✅ Réponse IA reçue : {decision['category']} / {decision['recommended_action']}")
        return decision
        
    except requests.exceptions.Timeout:
        print(f"[LM Client] ⏱️ Timeout lors de la requête LM Studio")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[LM Client] ❌ LM Studio inaccessible (vérifier si le serveur est démarré)")
        return None
    except json.JSONDecodeError as e:
        print(f"[LM Client] ⚠️ Réponse IA non-JSON : {ai_response[:100]}")
        return None
    except Exception as e:
        print(f"[LM Client] ❌ Erreur : {type(e).__name__} - {str(e)}")
        return None


# Test unitaire
if __name__ == "__main__":
    test_event = {
        "id": "test-1",
        "ts": "2025-11-11T10:00:00Z",
        "kind": "ssh_failed",
        "src_ip": "192.168.1.100",
        "raw": "Failed password for root from 192.168.1.100 port 22"
    }
    
    print("Test de connexion à LM Studio...")
    result = query_lm_studio(test_event)
    
    if result:
        print(f"\n✅ Test réussi !")
        print(json.dumps(result, indent=2))
    else:
        print("\n❌ Test échoué - Vérifier LM Studio")