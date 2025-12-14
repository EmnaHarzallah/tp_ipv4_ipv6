#!/usr/bin/env python3
"""
TP Fragmentation IPv4/IPv6 - Code principal
Envoyer des paquets LARGES pour forcer la fragmentation
et analyser les résultats.
"""

from scapy.all import *
import datetime
import sys
import time  # <-- AJOUT IMPORT MANQUANT
import os    # <-- AJOUT IMPORT MANQUANT

IPV4_DST = "8.8.8.8"                    # Google DNS IPv4
IPV6_DST = "2001:4860:4860::8888"       # Google DNS IPv6
PAYLOAD_SIZE = 2000                     # Taille > MTU pour fragmentation

# ================= FONCTIONS =====================
def create_fragmented_packets_ipv4(destination, payload_size):
    """Crée et envoie un gros paquet IPv4 qui sera fragmenté"""
    print(f"\n Envoi paquet IPv4 de {payload_size} octets vers {destination}")
    
    # Créer un payload personnalisé
    payload = "X" * payload_size
    
    # Paquet ICMP avec grand payload
    packet = IP(dst=destination)/ICMP()/payload
    
    print(f"   Taille totale: {len(packet)} octets")
    print(f"   Flags DF (Don't Fragment): {packet.flags}")
    
    # Envoyer le paquet
    send(packet, verbose=False)
    return packet

def create_fragmented_packets_ipv6(destination, payload_size):
    """Crée et envoie un paquet IPv6"""
    print(f"\n Envoi paquet IPv6 de {payload_size} octets vers {destination}")
    
    payload = "Y" * payload_size
    packet = IPv6(dst=destination)/ICMPv6EchoRequest()/payload
    
    print(f"   Taille totale: {len(packet)} octets")
    send(packet, verbose=False)
    return packet

def analyze_fragmentation(capture, protocol="IPv4"):
    """Analyse une capture pour détecter la fragmentation"""
    print(f"\n Analyse fragmentation {protocol}:")
    
    fragments_count = 0
    total_packets = len(capture)
    
    for i, pkt in enumerate(capture):
        if protocol == "IPv4" and IP in pkt:
            # Vérifier les flags de fragmentation IPv4
            flags = pkt[IP].flags
            offset = pkt[IP].frag
            
            if flags & 1 or offset > 0:  # MF flag ou offset > 0
                fragments_count += 1
                print(f"   Fragment {fragments_count}:")
                print(f"     ID: {hex(pkt[IP].id)}")
                print(f"     Offset: {offset}")
                print(f"     Flags: {flags}")
                print(f"     Taille: {len(pkt)} octets")
                print(f"     More Fragments: {'Oui' if flags & 1 else 'Non'}")
        
        elif protocol == "IPv6" and IPv6 in pkt:
            # Vérifier l'en-tête de fragmentation IPv6
            if IPv6ExtHdrFragment in pkt:
                fragments_count += 1
                frag = pkt[IPv6ExtHdrFragment]
                print(f"   Fragment {fragments_count}:")
                print(f"     Offset: {frag.offset}")
                print(f"     ID: {frag.id}")
                print(f"     Next Header: {frag.nh}")
                print(f"     More Fragments: {'Oui' if frag.m else 'Non'}")
    
    if total_packets > 0:
        percentage = (fragments_count / total_packets) * 100
        print(f"\n Résumé {protocol}:")
        print(f"   Paquets totaux: {total_packets}")
        print(f"   Fragments détectés: {fragments_count}")
        print(f"   Taux fragmentation: {percentage:.1f}%")
    else:
        print("   Aucun paquet capturé.")
    
    return fragments_count

# ================= PROGRAMME PRINCIPAL =================
def main():
    print("="*60)
    print("TP FRAGMENTATION IPv4/IPv6")
    print("="*60)
    
    # Demander à l'utilisateur
    print("\n DÉMARRER WIRESHARK AVANT DE CONTINUER!")
    print("   Filtre recommandé: 'ip or ipv6'")
    input("   Appuyez sur Entrée quand Wireshark est prêt...")
    
    # 1. Envoyer des paquets NON fragmentés (petits)
    print("\n" + "="*60)
    print("ÉTAPE 1: Paquets PETITS (pas de fragmentation)")
    print("="*60)
    
    # Petit paquet IPv4
    small_ipv4 = IP(dst=IPV4_DST)/ICMP()/"SMALL"
    send(small_ipv4, verbose=False)
    print(" Petit paquet IPv4 envoyé (68 octets)")
    
    # Petit paquet IPv6
    small_ipv6 = IPv6(dst=IPV6_DST)/ICMPv6EchoRequest()/"SMALL"
    send(small_ipv6, verbose=False)
    print(" Petit paquet IPv6 envoyé (68 octets)")
    
    # Pause pour capture
    print("\n Attente 3 secondes pour capture...")
    time.sleep(3)
    
    # 2. Envoyer des paquets GRANDS (fragmentation)
    print("\n" + "="*60)
    print("ÉTAPE 2: Paquets LARGES (avec fragmentation)")
    print("="*60)
    
    # Gros paquet IPv4 (sera fragmenté par les routeurs)
    print(f"\n Test IPv4 avec paquet de {PAYLOAD_SIZE} octets...")
    create_fragmented_packets_ipv4(IPV4_DST, PAYLOAD_SIZE)
    
    # Gros paquet IPv6 (fragmentation par l'émetteur si nécessaire)
    print(f"\n Test IPv6 avec paquet de {PAYLOAD_SIZE} octets...")
    create_fragmented_packets_ipv6(IPV6_DST, PAYLOAD_SIZE)
    
    # 3. Capture et analyse
    print("\n" + "="*60)
    print("ÉTAPE 3: Capture et analyse")
    print("="*60)
    
    print("\n Capture en cours (10 secondes)...")
    
    # Capture séparée IPv4 et IPv6
    print("\n📡 Capture IPv4...")
    capture_ipv4 = sniff(filter="ip", timeout=10)
    
    print("📡 Capture IPv6...")
    capture_ipv6 = sniff(filter="ip6", timeout=10)
    
    # Sauvegarde des captures
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    ipv4_file = f"capture_ipv4_{timestamp}.pcap"
    ipv6_file = f"capture_ipv6_{timestamp}.pcap"
    
    wrpcap(ipv4_file, capture_ipv4)
    wrpcap(ipv6_file, capture_ipv6)
    
    print(f"\n Captures sauvegardées:")
    print(f"   IPv4: {ipv4_file}")
    print(f"   IPv6: {ipv6_file}")
    
    # 4. Analyse
    print("\n" + "="*60)
    print("ÉTAPE 4: Analyse des résultats")
    print("="*60)
    
    frag_ipv4 = analyze_fragmentation(capture_ipv4, "IPv4")
    frag_ipv6 = analyze_fragmentation(capture_ipv6, "IPv6")
    
    # 5. Conclusions
    print("\n" + "="*60)
    print("CONCLUSIONS")
    print("="*60)
    
    print("\n Observations:")
    
    if frag_ipv4 > 0:
        print(" IPv4: Fragmentation détectée")
        print("   → Routeurs fragmentent les paquets trop grands")
        print("   → Champs utilisés: ID, Flags, Fragment Offset")
        print("   → More Fragments (MF): indique s'il y a d'autres fragments")
    else:
        print("  IPv4: Aucune fragmentation détectée")
        print("   → Paquet peut être < MTU du chemin")
        print("   → Ou flag DF (Don't Fragment) activé")
    
    if frag_ipv6 > 0:
        print(" IPv6: Fragmentation détectée")
        print("   → Émetteur doit fragmenter avant envoi")
        print("   → Utilise l'en-tête d'extension Fragment")
        print("   → Path MTU Discovery détermine la taille max")
    else:
        print("  IPv6: Aucune fragmentation détectée (normal)")
        print("   → IPv6 utilise Path MTU Discovery")
        print("   → Fragmentation uniquement par l'émetteur")
    
    print("\n Instructions pour le rapport:")
    print("1. Ouvrir les fichiers .pcap dans Wireshark")
    print("2. Filtrer: 'ip.flags.mf == 1' pour IPv4 fragments")
    print("3. Chercher 'IPv6 Fragment' pour IPv6")
    print("4. Comparer les mécanismes dans votre rapport")
    
    print("\n Exemple de tableau comparatif:")
    print("+---------------------+--------------------------------+--------------------------------+")
    print("| Caractéristique     | IPv4                           | IPv6                           |")
    print("+---------------------+--------------------------------+--------------------------------+")
    print("| Taille en-tête      | 20-60 octets (options)         | 40 octets (fixe)              |")
    print("| Fragmentation       | Routeurs intermédiaires       | Source seulement              |")
    print("| Champs frag         | ID, Flags, Offset             | En-tête extension Fragment    |")
    print("| MTU par défaut      | 576 octets                    | 1280 octets                   |")
    print("+---------------------+--------------------------------+--------------------------------+")
    
    print("\n" + "="*60)
    print("TP TERMINÉ - Analysez les captures dans Wireshark")
    print("="*60)

if __name__ == "__main__":
    # Vérifier les privilèges
    if os.name == 'posix' and os.geteuid() != 0:
        print(" Lancez avec sudo (besoin de droits root pour les sockets raw)")
        print("   Commande: sudo python3 tp_fragmentation.py")
        sys.exit(1)
    
    main()

