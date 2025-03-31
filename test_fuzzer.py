import requests
import random
import string
import time
import argparse
import json
import os
from datetime import datetime

# Configuration
def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def fuzz(target_url, param_name, method="GET"):
    payloads = [
        "' OR '1'='1" ,  # Injection SQL
        "<script>alert('XSS')</script>",  # XSS
        "../../../../etc/passwd",  # Directory Traversal
        "AAAAA" * 100,  # Buffer Overflow
        "%00",  # Null byte injection
        "' OR 1=1 --",  # SQL Injection
        "\"; DROP TABLE users; --"
    ]
    
    report = []
    
    for payload in payloads:
        params = {param_name: payload} if method == "GET" else {}
        data = {param_name: payload} if method == "POST" else None
        
        try:
            if method == "GET":
                response = requests.get(target_url, params=params, timeout=5)
            elif method == "POST":
                response = requests.post(target_url, data=data, timeout=5)
            else:
                print("Méthode HTTP non supportée")
                return
            
            print(f"Test avec payload: {payload}")
            print(f"Statut: {response.status_code}, Longueur: {len(response.text)}")
            
            result = {
                "payload": payload,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "potential_vulnerability": False
            }
            
            if "error" in response.text.lower() or response.status_code == 500:
                print(f"⚠️ Potentielle vulnérabilité détectée avec payload: {payload}")
                result["potential_vulnerability"] = True
            
            report.append(result)
            
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête: {e}")
            report.append({"payload": payload, "error": str(e)})
        
        time.sleep(1)
    
    # Génération d'un nom de fichier unique pour le rapport
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"fuzzing_report_{timestamp}.json"
    
    # Sauvegarde du rapport
    with open(report_filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"📄 Rapport de sécurité généré : {report_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzzer un site web pour détecter des failles de sécurité.")
    parser.add_argument("url", help="URL de la cible")
    parser.add_argument("param", help="Nom du paramètre à tester")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="Méthode HTTP à utiliser")
    
    args = parser.parse_args()
    print("Démarrage du fuzzing...")
    fuzz(args.url, args.param, args.method)
