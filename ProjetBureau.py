import nmap  # Bibliothèque pour effectuer des scans réseau
import socket  # Bibliothèque pour la résolution DNS et les connexions réseau
import platform  # Pour récupérer des informations sur le système d'exploitation
from scapy.all import ARP, Ether, srp  # Scapy pour effectuer un scan ARP
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading  # Pour exécuter des tâches en arrière-plan et éviter les blocages
import os  # Pour gérer les fichiers
from datetime import datetime  # Pour ajouter des timestamps aux rapports
import requests

def download_update(update_url, save_path):
    try:
        print("Téléchargement de la mise à jour...")
        response = requests.get(update_url, stream=True)
        with open(save_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        print(f"Mise à jour téléchargée : {save_path}")
    except Exception as e:
        print(f"Erreur lors du téléchargement : {e}")

def install_update(save_path):
    print("Installation de la mise à jour...")
    os.startfile(save_path)  # Lance l'exécutable ou l'installateur

current_version = "1.1.0"
latest_version_url = "https://github.com/DemoniX9710/ProjetBureau"
save_path = "C:\\Users\\kiera\\Downloads\\ProjetBureau"

download_update(latest_version_url, save_path)
install_update(save_path)

def thread_safe(func):
    """Décorateur pour exécuter des fonctions en thread afin d'éviter les blocages GUI."""
    def wrapper(*args, **kwargs):
        threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()
    return wrapper

# 1. Détecter les informations système
@thread_safe
def detect_system_info():
    try:
        system = platform.system()
        release = platform.release()
        version = platform.version()
        architecture = platform.architecture()[0]
        info = (f"Système d'exploitation : {system}\n"
                f"Version : {release}\n"
                f"Détails : {version}\n"
                f"Architecture : {architecture}")
        messagebox.showinfo("Informations système", info)
        return info
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue : {e}")
        return None

# 2. Scanner les ports ouverts sur une cible
@thread_safe
def scan_ports():
    target = simpledialog.askstring("Scan des ports", "Entrez l'adresse IP ou l'hôte cible :")
    if not target:
        return
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '1-65535')  # Scanner tous les ports (1-65535)
        results = []
        for host in nm.all_hosts():
            results.append(f"Hôte : {host} ({nm[host].hostname()})")
            results.append(f"État : {nm[host].state()}")
            if 'tcp' in nm[host]:
                results.append("Ports ouverts :")
                results.append("Port    | État    | Service        | Produit")
                results.append("--------------------------------------------------")
                for port in nm[host]['tcp']:
                    state = nm[host]['tcp'][port]['state']
                    name = nm[host]['tcp'][port]['name']
                    product = nm[host]['tcp'][port].get('product', 'N/A')
                    results.append(f"{port:<8}| {state:<8}| {name:<14}| {product}")
            else:
                results.append("Aucun port TCP ouvert détecté.")
        messagebox.showinfo("Résultats du scan des ports", "\n".join(results))
        return "\n".join(results)
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de scanner la cible {target} : {e}")
        return None

# 3. Scanner le réseau local (Scan ARP)
@thread_safe
def scan_local_network():
    network = simpledialog.askstring("Scan du réseau local", "Entrez la plage réseau (ex : 192.168.1.0/24) :")
    if not network:
        return
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        devices = []
        for sent, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        if devices:
            results = ["Appareils détectés :", "IP Address       | MAC Address", "-------------------------------------------"]
            for device in devices:
                results.append(f"{device['ip']:<16} | {device['mac']}")
            messagebox.showinfo("Résultats du scan réseau", "\n".join(results))
            return "\n".join(results)
        else:
            messagebox.showinfo("Résultats du scan réseau", "Aucun appareil détecté sur le réseau.")
            return "Aucun appareil détecté sur le réseau."
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors du scan réseau : {e}")
        return None

# 4. Vérification des vulnérabilités de base (exemple)
@thread_safe
def check_vulnerabilities():
    host = simpledialog.askstring("Vérification des vulnérabilités", "Entrez le nom d'hôte ou l'IP pour vérifier :")
    if not host:
        return
    try:
        response = socket.gethostbyname(host)
        result = [f"Le nom d'hôte {host} est résolu à l'adresse IP : {response}."]
        result.append(f"Tentative de connexion à {host} sur le port 80...")
        sock = socket.create_connection((host, 80), timeout=2)
        result.append(f"La connexion au port 80 a réussi : {host} est accessible.")
        sock.close()
        messagebox.showinfo("Vérification des vulnérabilités", "\n".join(result))
        return "\n".join(result)
    except socket.error as err:
        warning_msg = f"{host} semble inaccessible : {err}"
        messagebox.showwarning("Vérification des vulnérabilités", warning_msg)
        return warning_msg
    except Exception as e:
        error_msg = f"Une erreur est survenue : {e}"
        messagebox.showerror("Erreur", error_msg)
        return error_msg

# 5. Générer un rapport détaillé
@thread_safe
def generate_report():
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_path = os.path.join(os.getcwd(), f"rapport_securite_{timestamp}.txt")

        # Collecter les informations des différentes fonctions
        system_info = detect_system_info() or "Impossible de récupérer les informations système."
        port_scan_results = scan_ports() or "Aucun résultat de scan des ports."
        network_scan_results = scan_local_network() or "Aucun résultat de scan du réseau."
        vulnerability_results = check_vulnerabilities() or "Aucune vulnérabilité détectée."

        # Générer le contenu du rapport
        report_content = (
            f"Rapport de Sécurité - Généré le {timestamp}\n"
            f"============================================\n\n"
            f"1. Informations Système\n"
            f"-------------------------\n{system_info}\n\n"
            f"2. Résultats du Scan des Ports\n"
            f"--------------------------------\n{port_scan_results}\n\n"
            f"3. Résultats du Scan Réseau Local\n"
            f"-----------------------------------\n{network_scan_results}\n\n"
            f"4. Vérification des Vulnérabilités\n"
            f"-----------------------------------\n{vulnerability_results}\n"
        )

        # Enregistrer dans un fichier
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write(report_content)

        messagebox.showinfo("Rapport généré", f"Le rapport a été généré avec succès :\n{report_path}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors de la génération du rapport : {e}")

# Interface utilisateur principale
def main():
    root = tk.Tk()
    root.title("Outil de détection de failles de sécurité")
    root.geometry("500x400")

    tk.Label(root, text="Outil de détection de failles de sécurité", font=("Helvetica", 16, "bold"), pady=20).pack()

    tk.Button(root, text="1. Afficher les informations système", command=detect_system_info, width=50, pady=5).pack(pady=5)
    tk.Button(root, text="2. Scanner les ports d'un hôte", command=scan_ports, width=50, pady=5).pack(pady=5)
    tk.Button(root, text="3. Scanner le réseau local", command=scan_local_network, width=50, pady=5).pack(pady=5)
    tk.Button(root, text="4. Vérifier les vulnérabilités basiques", command=check_vulnerabilities, width=50, pady=5).pack(pady=5)
    tk.Button(root, text="5. Générer un rapport", command=generate_report, width=50, pady=5).pack(pady=5)
    tk.Button(root, text="Quitter", command=root.quit, width=50, pady=5).pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main()
