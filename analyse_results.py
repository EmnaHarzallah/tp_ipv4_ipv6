#!/usr/bin/env python3
"""
Analyse avancée des captures et génération de graphiques
"""

from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import sys
import os

def load_and_analyze_pcap(file_path):
    """Analyse détaillée d'un fichier pcap"""
    if not os.path.exists(file_path):
        print(f" Fichier non trouvé: {file_path}")
        return None
    
    packets = rdpcap(file_path)
    
    print(f" Analyse de {file_path}")
    print(f"   Nombre de paquets: {len(packets)}")
    
    if len(packets) == 0:
        print("     Capture vide!")
        return None
    
    # Statistiques
    stats = {
        'total': len(packets),
        'ipv4': 0,
        'ipv6': 0,
        'fragments_ipv4': 0,
        'fragments_ipv6': 0,
        'protocols': {},
        'sizes': []
    }
    
    for pkt in packets:
        stats['sizes'].append(len(pkt))
        
        if IP in pkt:
            stats['ipv4'] += 1
            
            # Vérifier fragmentation IPv4
            if pkt[IP].flags & 1 or pkt[IP].frag > 0:
                stats['fragments_ipv4'] += 1
            
            # Protocole
            proto = pkt[IP].proto
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
            
        elif IPv6 in pkt:
            stats['ipv6'] += 1
            
            # Vérifier fragmentation IPv6
            if IPv6ExtHdrFragment in pkt:
                stats['fragments_ipv6'] += 1
            
            # Protocole
            if hasattr(pkt[IPv6], 'nh'):
                proto = pkt[IPv6].nh
                stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
    
    return stats

def print_statistics(stats, protocol_name):
    """Affiche les statistiques"""
    if not stats:
        return
    
    print(f"\n Statistiques {protocol_name}:")
    print(f"   Paquets totaux: {stats['total']}")
    print(f"   Paquets IPv4: {stats['ipv4']}")
    print(f"   Paquets IPv6: {stats['ipv6']}")
    print(f"   Fragments IPv4: {stats['fragments_ipv4']}")
    print(f"   Fragments IPv6: {stats['fragments_ipv6']}")
    
    if stats['ipv4'] > 0:
        frag_rate = (stats['fragments_ipv4'] / stats['ipv4']) * 100
        print(f"   Taux fragmentation IPv4: {frag_rate:.1f}%")
    
    if stats['ipv6'] > 0:
        frag_rate = (stats['fragments_ipv6'] / stats['ipv6']) * 100
        print(f"   Taux fragmentation IPv6: {frag_rate:.1f}%")
    
    print("\n   Répartition par protocole:")
    for proto, count in stats['protocols'].items():
        proto_name = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6'
        }.get(proto, f'Proto {proto}')
        print(f"     {proto_name}: {count} paquets")

def create_comparison_chart(ipv4_stats, ipv6_stats, output_file="comparison.png"):
    """Crée un graphique de comparaison"""
    plt.figure(figsize=(12, 8))
    
    # Données pour le graphique
    labels = ['IPv4', 'IPv6']
    total_packets = [ipv4_stats['total'] if ipv4_stats else 0, 
                    ipv6_stats['total'] if ipv6_stats else 0]
    fragments = [ipv4_stats['fragments_ipv4'] if ipv4_stats else 0,
                ipv6_stats['fragments_ipv6'] if ipv6_stats else 0]
    
    # Graphique 1: Barres comparatives
    plt.subplot(2, 2, 1)
    x = np.arange(len(labels))
    width = 0.35
    
    plt.bar(x - width/2, total_packets, width, label='Total', color='skyblue')
    plt.bar(x + width/2, fragments, width, label='Fragments', color='lightcoral')
    
    plt.xlabel('Protocole')
    plt.ylabel('Nombre de paquets')
    plt.title('Comparaison IPv4 vs IPv6')
    plt.xticks(x, labels)
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # Graphique 2: Taux de fragmentation
    plt.subplot(2, 2, 2)
    fragmentation_rates = []
    
    if ipv4_stats and ipv4_stats['ipv4'] > 0:
        fragmentation_rates.append((ipv4_stats['fragments_ipv4'] / ipv4_stats['ipv4']) * 100)
    else:
        fragmentation_rates.append(0)
    
    if ipv6_stats and ipv6_stats['ipv6'] > 0:
        fragmentation_rates.append((ipv6_stats['fragments_ipv6'] / ipv6_stats['ipv6']) * 100)
    else:
        fragmentation_rates.append(0)
    
    colors = ['red' if rate > 0 else 'green' for rate in fragmentation_rates]
    plt.bar(labels, fragmentation_rates, color=colors)
    plt.ylabel('Fragmentation (%)')
    plt.title('Taux de fragmentation')
    plt.grid(True, alpha=0.3)
    
    # Graphique 3: Distribution des tailles
    plt.subplot(2, 2, 3)
    if ipv4_stats and ipv4_stats['sizes']:
        plt.hist(ipv4_stats['sizes'], bins=20, alpha=0.7, label='IPv4', color='blue')
    if ipv6_stats and ipv6_stats['sizes']:
        plt.hist(ipv6_stats['sizes'], bins=20, alpha=0.7, label='IPv6', color='green')
    
    plt.xlabel('Taille (octets)')
    plt.ylabel('Fréquence')
    plt.title('Distribution des tailles')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # Graphique 4: Répartition protocolaire (exemple)
    plt.subplot(2, 2, 4)
    protocols = ['ICMP', 'TCP', 'UDP', 'Autres']
    counts = [150, 800, 450, 100]  # Données d'exemple
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
    plt.title('Répartition des protocoles')
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    print(f"\n Graphique sauvegardé: {output_file}")
    plt.show()

def main():
    print("="*50)
    print("ANALYSE DES CAPTURES - TP FRAGMENTATION")
    print("="*50)
    
    # Chercher les fichiers de capture récents
    pcap_files = [f for f in os.listdir('.') if f.startswith('capture_') and f.endswith('.pcap')]
    
    if not pcap_files:
        print(" Aucun fichier de capture trouvé.")
        print("   Exécutez d'abord tp_fragmentation.py")
        sys.exit(1)
    
    print("\n Fichiers de capture trouvés:")
    for i, f in enumerate(pcap_files):
        print(f"   {i+1}. {f}")
    
    # Analyser les fichiers
    ipv4_stats = None
    ipv6_stats = None
    
    for file in pcap_files:
        if 'ipv4' in file.lower():
            print(f"\n{'='*30}")
            print(f"Analyse IPv4: {file}")
            print('='*30)
            ipv4_stats = load_and_analyze_pcap(file)
            print_statistics(ipv4_stats, "IPv4")
        
        elif 'ipv6' in file.lower():
            print(f"\n{'='*30}")
            print(f"Analyse IPv6: {file}")
            print('='*30)
            ipv6_stats = load_and_analyze_pcap(file)
            print_statistics(ipv6_stats, "IPv6")
    
    # Générer le graphique
    if ipv4_stats or ipv6_stats:
        print("\n Génération du graphique de comparaison...")
        create_comparison_chart(ipv4_stats, ipv6_stats)
    
    print("\n" + "="*50)
    print("ANALYSE TERMINÉE")
    print("="*50)

if __name__ == "__main__":
    main()