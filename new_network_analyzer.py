#!/usr/bin/env python3
import os
import pyshark
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
from fpdf import FPDF
import geoip2.database
import warnings
import PyPDF2
import time
from threading import Thread
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import subprocess
import math

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ------------------------
# GeoLite2 database
# ------------------------
GEO_DB_PATH = "GeoLite2-City.mmdb"
geo_reader = geoip2.database.Reader(GEO_DB_PATH) if os.path.exists(GEO_DB_PATH) else None

def get_geo(ip):
    try:
        if not geo_reader:
            return "Unknown/Unknown/Unknown"
        if ip.startswith(("10.", "192.168.", "172.")):
            return "Private/Private/Private"
        response = geo_reader.city(ip)
        country = response.country.name or "-"
        region = response.subdivisions.most_specific.name or "-"
        city = response.city.name or "-"
        return f"{country}/{region}/{city}"
    except:
        return "Unknown/Unknown/Unknown"

def safe_int(val, default=0):
    try:
        return int(val)
    except:
        return default

# ------------------------
# Protocol Diversity Analysis
# ------------------------
def analyze_protocol_diversity(protocol_distribution, packets_data):
    """Enhanced protocol analysis to detect ANY protocol monoculture patterns"""
    alerts = []
    
    if not protocol_distribution:
        return alerts
    
    total_packets = sum(protocol_distribution.values())
    if total_packets == 0:
        return alerts
    
    # Calculate protocol concentration
    sorted_protocols = sorted(protocol_distribution.items(), key=lambda x: x[1], reverse=True)
    top_protocol, top_count = sorted_protocols[0]
    top_percentage = (top_count / total_packets) * 100
    
    # High-risk protocols that indicate specific attacks
    high_risk_protocols = {
        'DCERPC': 'lateral movement or exploitation',
        'SMB': 'file sharing attacks or lateral movement', 
        'RDP': 'remote desktop brute force',
        'SSH': 'SSH brute force attacks',
        'TELNET': 'unencrypted remote access',
        'FTP': 'unencrypted file transfer',
        'SNMP': 'network device exploitation',
        'NETBIOS': 'Windows network reconnaissance'
    }
    
    # Alert on ANY protocol monoculture (>80%)
    if top_percentage > 80.0:
        risk_context = high_risk_protocols.get(top_protocol, "unusual network behavior")
        alerts.append({
            'type': 'PROTOCOL_MONOCULTURE',
            'severity': 'HIGH',
            'message': f"Protocol dominance: {top_protocol} constitutes {top_percentage:.1f}% of traffic - possible {risk_context}",
            'risk_score': min(95, 70 + (top_percentage - 80)),
            'recommendation': f'Investigate {top_protocol} traffic patterns for malicious activity'
        })
    
    # Special high-risk protocol alerts (lower threshold)
    for protocol, description in high_risk_protocols.items():
        if protocol in protocol_distribution:
            protocol_pct = (protocol_distribution[protocol] / total_packets) * 100
            if protocol_pct > 30.0:  # Lower threshold for high-risk protocols
                alerts.append({
                    'type': f'{protocol}_DOMINANCE',
                    'severity': 'CRITICAL' if protocol in ['DCERPC', 'SMB', 'RDP'] else 'HIGH',
                    'message': f"High {protocol} traffic: {protocol_pct:.1f}% - possible {description}",
                    'risk_score': 90 if protocol in ['DCERPC', 'SMB', 'RDP'] else 80,
                    'recommendation': f'Immediate investigation required for {protocol} traffic'
                })
    
    # Calculate protocol entropy (diversity metric)
    entropy = calculate_protocol_entropy(protocol_distribution)
    if entropy < 1.0:  # Low diversity threshold
        alerts.append({
            'type': 'LOW_PROTOCOL_ENTROPY',
            'severity': 'MEDIUM',
            'message': f"Low protocol diversity (entropy: {entropy:.2f}) - network traffic lacks normal mixed patterns",
            'risk_score': 60,
            'recommendation': 'Review for specialized malware, beaconing, or C2 communication'
        })
    
    # Alert if too few protocols for traffic volume
    if total_packets > 100 and len(protocol_distribution) < 3:
        alerts.append({
            'type': 'PROTOCOL_POVERTY',
            'severity': 'MEDIUM', 
            'message': f"Limited protocol variety: {len(protocol_distribution)} protocols for {total_packets} packets",
            'risk_score': 50,
            'recommendation': 'Expected more protocol diversity for this traffic volume'
        })
    
    return alerts

def calculate_protocol_entropy(protocol_distribution):
    """Calculate Shannon entropy of protocol distribution"""
    total = sum(protocol_distribution.values())
    if total == 0:
        return 0
    
    entropy = 0
    for count in protocol_distribution.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

# ------------------------
# Performance Optimization
# ------------------------
def process_single_packet(pkt):
    """Process individual packet - optimized version"""
    ip_count = Counter()
    port_count = Counter()
    proto_count = Counter()
    basic_info = {}
    
    try:
        if hasattr(pkt, 'ip'):
            src, dst = pkt.ip.src, pkt.ip.dst
            ip_count.update([src, dst])
            
            if hasattr(pkt, 'tcp'):
                sport, dport = pkt.tcp.srcport, pkt.tcp.dstport
            elif hasattr(pkt, 'udp'):
                sport, dport = pkt.udp.srcport, pkt.udp.dstport
            else:
                sport, dport = None, None
                
            if sport: port_count.update([sport])
            if dport: port_count.update([dport])
            
            basic_info = {
                'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
                'length': safe_int(getattr(pkt, 'length', 0)),
                'protocol': getattr(pkt, 'highest_layer', '-'),
                'timestamp': getattr(pkt, 'sniff_time', datetime.now())
            }
            
        proto_count.update([getattr(pkt, 'highest_layer', '-')])
        
    except Exception:
        pass
    
    return ip_count, port_count, proto_count, basic_info

def optimized_pcap_analysis(file):
    """Optimized analysis for large PCAP files"""
    print(f"🔧 Optimizing analysis for large file: {file}")
    
    ip_counter = Counter()
    port_counter = Counter()
    proto_counter = Counter()
    all_packets_data = []
    
    cap = pyshark.FileCapture(file, keep_packets=False, use_json=True)
    
    chunk_size = 5000
    current_chunk = []
    packet_count = 0
    
    for pkt in cap:
        current_chunk.append(pkt)
        packet_count += 1
        
        if len(current_chunk) >= chunk_size:
            with ThreadPoolExecutor(max_workers=min(4, mp.cpu_count())) as executor:
                results = list(executor.map(process_single_packet, current_chunk))
            
            for ip_count, port_count, proto_count, basic_info in results:
                ip_counter.update(ip_count)
                port_counter.update(port_count)
                proto_counter.update(proto_count)
                if basic_info:
                    all_packets_data.append(basic_info)
            
            current_chunk = []
            print(f"📊 Processed {packet_count} packets...")
    
    # Process remaining packets
    if current_chunk:
        with ThreadPoolExecutor(max_workers=min(4, mp.cpu_count())) as executor:
            results = list(executor.map(process_single_packet, current_chunk))
        
        for ip_count, port_count, proto_count, basic_info in results:
            ip_counter.update(ip_count)
            port_counter.update(port_count)
            proto_counter.update(proto_count)
            if basic_info:
                all_packets_data.append(basic_info)
    
    print(f"✅ Completed analysis of {packet_count} packets")
    return ip_counter, port_counter, proto_counter, all_packets_data

# ------------------------
# Enhanced Statistical Analysis
# ------------------------
def enhanced_statistical_analysis(packets_data):
    """Comprehensive statistical analysis"""
    if not packets_data:
        return {}
    
    packet_sizes = [pkt['length'] for pkt in packets_data if 'length' in pkt]
    protocols = [pkt.get('protocol', 'UNKNOWN') for pkt in packets_data]
    
    protocol_stats = {}
    for protocol in set(protocols):
        proto_sizes = [pkt['length'] for pkt in packets_data if pkt.get('protocol') == protocol]
        if proto_sizes:
            protocol_stats[protocol] = {
                'count': len(proto_sizes),
                'avg_size': np.mean(proto_sizes),
                'total_bytes': sum(proto_sizes),
                'size_std': np.std(proto_sizes)
            }
    
    if packet_sizes:
        stats = {
            'packet_size_stats': {
                'mean': np.mean(packet_sizes),
                'std': np.std(packet_sizes),
                'min': min(packet_sizes),
                'max': max(packet_sizes),
                'percentiles': {
                    '25': np.percentile(packet_sizes, 25),
                    '50': np.percentile(packet_sizes, 50),
                    '75': np.percentile(packet_sizes, 75),
                    '95': np.percentile(packet_sizes, 95)
                }
            },
            'total_packets': len(packets_data),
            'total_bytes': sum(packet_sizes),
            'protocol_stats': protocol_stats,
            'throughput_analysis': calculate_throughput_analysis(packets_data)
        }
    else:
        stats = {}
    
    return stats

def calculate_throughput_analysis(packets_data):
    """Calculate network throughput over time"""
    if not packets_data:
        return {}
    
    # Group by time windows (1-minute intervals)
    throughput_data = defaultdict(int)
    for pkt in packets_data:
        if 'timestamp' in pkt:
            minute_key = pkt['timestamp'].replace(second=0, microsecond=0)
            throughput_data[minute_key] += pkt.get('length', 0)
    
    throughput_list = [{'time': k, 'bytes': v} for k, v in sorted(throughput_data.items())]
    
    if len(throughput_list) > 1:
        bytes_per_sec = sum(item['bytes'] for item in throughput_list) / (len(throughput_list) * 60)
    else:
        bytes_per_sec = 0
    
    return {
        'throughput_timeline': throughput_list,
        'avg_bytes_per_second': bytes_per_sec,
        'avg_mbps': (bytes_per_sec * 8) / 1_000_000
    }

# ------------------------
# Machine Learning Anomaly Detection
# ------------------------
class NetworkAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def extract_features(self, packets_data):
        """Extract features for ML analysis"""
        features = []
        
        for pkt in packets_data:
            feature_vector = [
                pkt.get('length', 0),
                1 if pkt.get('sport') and pkt['sport'].isdigit() and int(pkt['sport']) < 1024 else 0,
                1 if pkt.get('dport') and pkt['dport'].isdigit() and int(pkt['dport']) < 1024 else 0,
                len(pkt.get('src', '')),
                len(pkt.get('dst', '')),
            ]
            
            protocol = pkt.get('protocol', '').lower()
            protocol_features = [
                1 if 'tcp' in protocol else 0,
                1 if 'udp' in protocol else 0,
                1 if 'dns' in protocol else 0,
                1 if 'http' in protocol else 0,
            ]
            feature_vector.extend(protocol_features)
                
            features.append(feature_vector)
        
        return np.array(features)
    
    def detect_anomalies(self, packets_data):
        """Detect anomalous network traffic"""
        if len(packets_data) < 10:
            print("⚠️ Need at least 10 packets for meaningful anomaly detection")
            return []
            
        features = self.extract_features(packets_data)
        
        if not self.is_fitted:
            features_scaled = self.scaler.fit_transform(features)
            self.model.fit(features_scaled)
            self.is_fitted = True
        else:
            features_scaled = self.scaler.transform(features)
        
        predictions = self.model.predict(features_scaled)
        anomalies = [i for i, pred in enumerate(predictions) if pred == -1]
        
        return anomalies

# ------------------------
# Enhanced TLS/SSL Analysis
# ------------------------
def analyze_encrypted_traffic(pkt):
    """Enhanced TLS/SSL traffic analysis"""
    tls_insights = []
    
    if hasattr(pkt, 'tls'):
        try:
            if hasattr(pkt.tls, 'handshake_type'):
                handshake_type = pkt.tls.handshake_type
                tls_insights.append(f"TLS Handshake: {handshake_type}")
            
            if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                sni = pkt.tls.handshake_extensions_server_name
                tls_insights.append(f"TLS SNI: {sni}")
            
            if hasattr(pkt.tls, 'handshake_ciphersuite'):
                cipher = pkt.tls.handshake_ciphersuite
                tls_insights.append(f"TLS Cipher: {cipher}")
            
            if hasattr(pkt.tls, 'handshake_certificate'):
                cert_length = len(str(pkt.tls.handshake_certificate))
                tls_insights.append(f"Certificate size: {cert_length} bytes")
                
        except Exception as e:
            tls_insights.append(f"TLS Analysis Error: {str(e)}")
    
    return tls_insights

# ------------------------
# Network Mapping
# ------------------------
class NetworkMapper:
    def __init__(self):
        self.devices = defaultdict(dict)
        self.connections = []
    
    def build_network_map(self, packets_data):
        """Build network device relationship map"""
        for pkt in packets_data:
            try:
                src = pkt.get('src')
                dst = pkt.get('dst')
                protocol = pkt.get('protocol', 'UNKNOWN')
                
                if src and dst:
                    if src not in self.devices:
                        self.devices[src] = {
                            'geo': get_geo(src),
                            'first_seen': pkt.get('timestamp', datetime.now()),
                            'last_seen': pkt.get('timestamp', datetime.now()),
                            'packet_count': 1
                        }
                    else:
                        self.devices[src]['last_seen'] = pkt.get('timestamp', datetime.now())
                        self.devices[src]['packet_count'] += 1
                    
                    if dst not in self.devices:
                        self.devices[dst] = {
                            'geo': get_geo(dst),
                            'first_seen': pkt.get('timestamp', datetime.now()),
                            'last_seen': pkt.get('timestamp', datetime.now()),
                            'packet_count': 1
                        }
                    else:
                        self.devices[dst]['last_seen'] = pkt.get('timestamp', datetime.now())
                        self.devices[dst]['packet_count'] += 1
                    
                    self.connections.append({
                        'source': src,
                        'target': dst,
                        'protocol': protocol,
                        'timestamp': pkt.get('timestamp', datetime.now()),
                        'size': pkt.get('length', 0)
                    })
                    
            except Exception:
                continue
        
        return {
            'devices': dict(self.devices),
            'connections': self.connections,
            'topology_metrics': self.calculate_topology_metrics()
        }
    
    def calculate_topology_metrics(self):
        """Calculate network topology metrics"""
        total_devices = len(self.devices)
        total_connections = len(self.connections)
        
        connection_density = total_connections / max(total_devices, 1)
        
        return {
            'total_devices': total_devices,
            'total_connections': total_connections,
            'connection_density': connection_density,
            'internal_external_ratio': self.calculate_internal_external_ratio()
        }
    
    def calculate_internal_external_ratio(self):
        """Calculate ratio of internal to external communications"""
        internal_comms = 0
        external_comms = 0
        
        for conn in self.connections:
            src_internal = conn['source'].startswith(('10.', '192.168.', '172.')) if conn['source'] else False
            dst_internal = conn['target'].startswith(('10.', '192.168.', '172.')) if conn['target'] else False
            
            if src_internal and dst_internal:
                internal_comms += 1
            else:
                external_comms += 1
        
        return {'internal': internal_comms, 'external': external_comms}

# ------------------------
# Enhanced Visualization
# ------------------------
def visualize_enhanced_summary():
    if not os.path.exists("enhanced_summary.json"):
        print("❌ enhanced_summary.json not found. Run analysis first.")
        return
        
    with open("enhanced_summary.json") as f:
        summary = json.load(f)

    # Create a cleaner layout with better spacing
    fig = plt.figure(figsize=(16, 12))
    
    # Define the grid layout properly
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
    
    # Top Talkers - Top left (larger)
    ax1 = fig.add_subplot(gs[0, 0])
    # Protocol Distribution - Top right (larger pie chart)
    ax2 = fig.add_subplot(gs[0, 1])
    # Top Ports - Middle left
    ax3 = fig.add_subplot(gs[1, 0])
    # Packet Size Distribution - Middle right  
    ax4 = fig.add_subplot(gs[1, 1])
    # Throughput Timeline - Bottom row (span full width)
    ax5 = fig.add_subplot(gs[2, :])

    # 1. Top Talkers - Clean bar chart
    if summary['top_talkers']:
        ips, counts = zip(*summary['top_talkers'][:8])
        bars = ax1.bar(range(len(ips)), counts, color='#2E86AB', alpha=0.8, edgecolor='black', linewidth=0.5)
        ax1.set_title("Top Talkers (IP Addresses)", fontsize=12, fontweight='bold', pad=10)
        ax1.set_ylabel("Packet Count", fontsize=10)
        ax1.set_xticks(range(len(ips)))
        ax1.set_xticklabels([ip[:15] + '...' if len(ip) > 15 else ip for ip in ips], 
                           rotation=45, ha='right', fontsize=8)
        
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                    f'{count}', ha='center', va='bottom', fontsize=8)

    # 2. Protocol Distribution - Clean, visible pie chart
    if summary['protocol_distribution']:
        protocols = list(summary['protocol_distribution'].keys())
        counts = list(summary['protocol_distribution'].values())
        
        # Filter out very small protocols (less than 1%)
        total = sum(counts)
        filtered_data = [(p, c) for p, c in zip(protocols, counts) if c/total >= 0.01]
        if filtered_data:
            protocols, counts = zip(*filtered_data)
        else:
            protocols, counts = protocols[:10], counts[:10]
        
        colors = plt.cm.Set3(np.linspace(0, 1, len(protocols)))
        
        wedges, texts, autotexts = ax2.pie(counts, labels=protocols, autopct='%1.1f%%', 
                                          startangle=90, colors=colors, 
                                          textprops={'fontsize': 9})
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(8)
        
        for text in texts:
            text.set_fontsize(9)
            
        ax2.set_title("Protocol Distribution", fontsize=12, fontweight='bold', pad=10)

    # 3. Top Ports - Clean bar chart
    if summary['top_ports']:
        ports, counts = zip(*summary['top_ports'][:10])
        bars = ax3.bar(range(len(ports)), counts, color='#A23B72', alpha=0.8, edgecolor='black', linewidth=0.5)
        ax3.set_title("Top Ports", fontsize=12, fontweight='bold', pad=10)
        ax3.set_ylabel("Connection Count", fontsize=10)
        ax3.set_xticks(range(len(ports)))
        ax3.set_xticklabels(ports, rotation=45, ha='right', fontsize=9)
        
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                    f'{count}', ha='center', va='bottom', fontsize=8)

    # 4. Packet Size Distribution - Box plot style
    stats = summary.get('enhanced_statistics', {})
    if stats and 'packet_size_stats' in stats:
        ps_stats = stats['packet_size_stats']
        metrics = ['Min', '25%', 'Median', '75%', 'Max']
        values = [ps_stats['min'], 
                 ps_stats['percentiles']['25'],
                 ps_stats['percentiles']['50'], 
                 ps_stats['percentiles']['75'],
                 ps_stats['max']]
        
        bars = ax4.bar(metrics, values, color='#F18F01', alpha=0.8, edgecolor='black', linewidth=0.5)
        ax4.set_title("Packet Size Distribution (bytes)", fontsize=12, fontweight='bold', pad=10)
        ax4.set_ylabel("Bytes", fontsize=10)
        ax4.tick_params(axis='x', rotation=45)
        ax4.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))
        
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + max(values)*0.01,
                    f'{value:,}', ha='center', va='bottom', fontsize=8, rotation=0)

    # 5. Throughput Timeline - Clean line chart
    throughput_data = stats.get('throughput_analysis', {}).get('throughput_timeline', [])
    if throughput_data:
        times = [datetime.fromisoformat(item['time'].replace('Z', '+00:00')) if isinstance(item['time'], str) else item['time'] for item in throughput_data]
        bytes_data = [item['bytes'] for item in throughput_data]
        
        ax5.plot(times, bytes_data, marker='o', linewidth=2, markersize=4, 
                color='#C73E1D', alpha=0.8, markerfacecolor='white', markeredgewidth=1)
        ax5.set_title("Network Throughput Over Time", fontsize=12, fontweight='bold', pad=10)
        ax5.set_xlabel("Time", fontsize=10)
        ax5.set_ylabel("Bytes per Minute", fontsize=10)
        ax5.tick_params(axis='x', rotation=45)
        ax5.grid(True, alpha=0.3)
        ax5.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))

    # Remove empty subplots if data is missing
    if not summary['top_talkers']:
        fig.delaxes(ax1)
    if not summary['protocol_distribution']:
        fig.delaxes(ax2)
    if not summary['top_ports']:
        fig.delaxes(ax3)
    if not stats or 'packet_size_stats' not in stats:
        fig.delaxes(ax4)
    if not throughput_data:
        fig.delaxes(ax5)

    # Protocol Diversity Analysis Display
    protocol_alerts = analyze_protocol_diversity(summary.get('protocol_distribution', {}), [])
    if protocol_alerts:
        print(f"\n🚨 Protocol Diversity Alerts ({len(protocol_alerts)}):")
        for alert in protocol_alerts:
            print(f"   [{alert['severity']}] {alert['message']}")

    # Main title
    plt.suptitle("Enhanced Network Analysis Dashboard", fontsize=16, fontweight='bold', y=0.98)
    
    plt.tight_layout()
    plt.show()

# ------------------------
# PCAP selection
# ------------------------
def select_pcap():
    pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap')]
    if not pcap_files:
        print("❌ No PCAP files found in current directory.")
        return None

    print("Available PCAP files:")
    for idx, file in enumerate(pcap_files, 1):
        size = os.path.getsize(file) / (1024*1024)
        print(f"{idx}. {file} ({size:.2f} MB)")

    while True:
        choice = input(f"Enter PCAP number (1-{len(pcap_files)}): ")
        if choice.isdigit() and 1 <= int(choice) <= len(pcap_files):
            return pcap_files[int(choice)-1]
        print("❌ Invalid selection. Try again.")

# ------------------------
# Enhanced Analyze PCAP
# ------------------------
def analyze_pcap():
    file = select_pcap()
    if not file:
        return

    file_size = os.path.getsize(file) / (1024*1024)
    
    if file_size > 10:
        print("🔄 Using optimized analysis for large file...")
        ip_counter, port_counter, proto_counter, packets_data = optimized_pcap_analysis(file)
    else:
        print("🔄 Using standard analysis...")
        cap = pyshark.FileCapture(file, keep_packets=False)
        packets_data = []
        ip_counter, port_counter, proto_counter = Counter(), Counter(), Counter()
        
        for pkt in cap:
            try:
                if hasattr(pkt, 'ip'):
                    src, dst = pkt.ip.src, pkt.ip.dst
                    ip_counter.update([src, dst])
                    
                    if hasattr(pkt, 'tcp'):
                        sport, dport = pkt.tcp.srcport, pkt.tcp.dstport
                    elif hasattr(pkt, 'udp'):
                        sport, dport = pkt.udp.srcport, pkt.udp.dstport
                    else:
                        sport, dport = None, None
                        
                    if sport: port_counter.update([sport])
                    if dport: port_counter.update([dport])
                    
                    packets_data.append({
                        'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
                        'length': safe_int(getattr(pkt, 'length', 0)),
                        'protocol': getattr(pkt, 'highest_layer', '-'),
                        'timestamp': getattr(pkt, 'sniff_time', datetime.now())
                    })
                    
                proto_counter.update([getattr(pkt, 'highest_layer', '-')])
            except:
                continue

    # Enhanced statistical analysis
    print("📈 Running enhanced statistical analysis...")
    stats = enhanced_statistical_analysis(packets_data)
    
    # Network topology mapping
    print("🗺️ Building network topology...")
    mapper = NetworkMapper()
    topology = mapper.build_network_map(packets_data)
    
    # ML Anomaly Detection
    print("🤖 Running ML anomaly detection...")
    detector = NetworkAnomalyDetector()
    anomalies = detector.detect_anomalies(packets_data)
    
    # Protocol Diversity Analysis
    print("🔍 Running protocol diversity analysis...")
    protocol_alerts = analyze_protocol_diversity(proto_counter, packets_data)
    
    # Generate comprehensive summary
    summary = {
        'top_talkers': ip_counter.most_common(10),
        'top_ports': port_counter.most_common(10),
        'protocol_distribution': dict(proto_counter),
        'enhanced_statistics': stats,
        'network_topology': topology,
        'anomaly_detection': {
            'total_anomalies': len(anomalies),
            'anomaly_percentage': (len(anomalies) / len(packets_data)) * 100 if packets_data else 0,
            'anomalous_packets': [packets_data[i] for i in anomalies] if anomalies else []
        },
        'protocol_diversity_alerts': protocol_alerts,
        'analysis_timestamp': datetime.now().isoformat()
    }

    with open('enhanced_summary.json','w') as f:
        json.dump(summary, f, indent=4, default=str)

    # Enhanced PDF Report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200,10,"Enhanced Network Traffic Report", ln=True, align="C")
    pdf.ln(8)
    
    # Statistical Overview
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0,8,"Statistical Overview:", ln=True)
    pdf.set_font("Arial", '', 11)
    
    if stats:
        pdf.cell(0,7,f"Total Packets: {stats.get('total_packets', 0)}", ln=True)
        pdf.cell(0,7,f"Total Bytes: {stats.get('total_bytes', 0):,}", ln=True)
        pdf.cell(0,7,f"Average Packet Size: {stats.get('packet_size_stats', {}).get('mean', 0):.2f} bytes", ln=True)
        pdf.cell(0,7,f"Average Throughput: {stats.get('throughput_analysis', {}).get('avg_mbps', 0):.2f} Mbps", ln=True)
    
    pdf.ln(5)
    
    # Network Topology
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0,8,"Network Topology:", ln=True)
    pdf.set_font("Arial", '', 11)
    pdf.cell(0,7,f"Total Devices: {topology.get('topology_metrics', {}).get('total_devices', 0)}", ln=True)
    pdf.cell(0,7,f"Total Connections: {topology.get('topology_metrics', {}).get('total_connections', 0)}", ln=True)
    
    pdf.ln(5)
    
    # Anomaly Detection
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0,8,"ML Anomaly Detection:", ln=True)
    pdf.set_font("Arial", '', 11)
    pdf.cell(0,7,f"Detected Anomalies: {len(anomalies)} ({summary['anomaly_detection']['anomaly_percentage']:.2f}%)", ln=True)
    
    # Protocol Diversity Alerts
    if protocol_alerts:
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0,8,"Protocol Diversity Alerts:", ln=True)
        pdf.set_font("Arial", '', 11)
        for alert in protocol_alerts[:3]:
            pdf.cell(0,7,f"[{alert['severity']}] {alert['message']}", ln=True)
    
    if anomalies:
        pdf.cell(0,7,"Top Anomalous Flows:", ln=True)
        for i, anomaly_idx in enumerate(anomalies[:5]):
            pkt = packets_data[anomaly_idx]
            pdf.cell(0,7,f"  {pkt.get('src', '?')}:{pkt.get('sport', '?')} -> {pkt.get('dst', '?')}:{pkt.get('dport', '?')} ({pkt.get('protocol', '?')})", ln=True)

    pdf.output("enhanced_report.pdf")
    
    # Print summary
    print("✅ Enhanced logs, summary, and report generated successfully!")
    print(f"📊 Statistics: {stats.get('total_packets', 0)} packets analyzed")
    print(f"🤖 ML Results: {len(anomalies)} anomalies detected")
    print(f"🗺️ Topology: {topology['topology_metrics']['total_devices']} devices mapped")
    
    if protocol_alerts:
        print(f"🚨 Protocol Diversity Alerts: {len(protocol_alerts)}")
        for alert in protocol_alerts:
            print(f"   [{alert['severity']}] {alert['message']}")

# ------------------------
# Live Monitoring
# ------------------------
def live_monitor(interface=None):
    pcap_name = input("Enter filename to save live capture (without .pcap): ").strip()
    if not pcap_name:
        print("⚠️ Capture not saved. Exiting live monitor.")
        return

    pcap_file = f"{pcap_name}.pcap"
    print("⚡ Starting live capture on interface:", interface or "default")
    print("🛑 Press Ctrl+C to stop capture anytime.")

    cap = pyshark.LiveCapture(interface=interface, output_file=pcap_file)
    try:
        cap.sniff()
    except KeyboardInterrupt:
        print("\n🛑 Live monitoring stopped by user.")
    finally:
        cap.close()
        print(f"✅ Live capture saved as {pcap_file}")

# ------------------------
# Open Enhanced PDF
# ------------------------
def open_enhanced_pdf(filename="enhanced_report.pdf"):
    if not os.path.exists(filename):
        print(f"❌ {filename} not found. Run analysis first.")
        return
    
    try:
        if os.name == 'posix':
            viewers = ['xdg-open', 'evince', 'okular', 'atril', 'qpdfview', 'mupdf']
            for viewer in viewers:
                if subprocess.run(['which', viewer], capture_output=True).returncode == 0:
                    subprocess.Popen([viewer, filename])
                    print(f"✅ Opening PDF with {viewer}: {filename}")
                    return
            
            os.system(f'xdg-open "{filename}" 2>/dev/null &')
            print(f"✅ Opening PDF: {filename}")
        
        elif os.name == 'nt':
            os.system(f'start "" "{filename}"')
            print(f"✅ Opening PDF: {filename}")
        
        elif os.name == 'darwin':
            os.system(f'open "{filename}"')
            print(f"✅ Opening PDF: {filename}")
        
        else:
            print(f"📄 PDF generated: {filename}")
            print("Please open the file manually with your PDF viewer.")
        
    except Exception as e:
        print(f"❌ Could not open PDF automatically: {e}")
        print(f"📄 Please open {filename} manually with your PDF viewer.")

# ------------------------
# Read PDF (Legacy function)
# ------------------------
def read_pdf(filename="report.pdf"):
    if not os.path.exists(filename):
        print(f"❌ {filename} not found. Run analysis first.")
        return
    with open(filename,"rb") as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            print(page.extract_text())

# ------------------------
# Delete Enhanced Logs
# ------------------------
def delete_enhanced_logs():
    files_to_delete = []
    for f in os.listdir('.'):
        if f.endswith(('.log', '.pdf', '.json')) and ('enhanced' in f or 'report' in f or 'summary' in f):
            files_to_delete.append(f)
    
    for f in files_to_delete:
        os.remove(f)
        print(f"🗑️ Deleted {f}")
    
    print(f"✅ {len(files_to_delete)} log files and reports deleted. PCAP files are safe.")

# ------------------------
# Enhanced Main Menu
# ------------------------
# ------------------------
# Enhanced Main Menu (UPDATED)
# ------------------------
# ------------------------
# Enhanced Main Menu (FIXED)
# ------------------------
def main():
    while True:
        print("\n" + "="*50)
        print("           ENHANCED NETWORK ANALYZER")
        print("="*50)
        print("1. Analyze PCAP (Enhanced)")
        print("2. Open Interactive Dashboard") 
        print("3. Open Enhanced Report PDF")
        print("4. Delete Logs / Reports")
        print("5. Live Monitoring & Analysis")
        print("6. Network Topology View")
        print("7. ML Anomaly Detection Only")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == '1':
            analyze_pcap()
        elif choice == '2':
            # Simple dashboard launcher
            launch_dashboard_simple()
        elif choice == '3':
            open_enhanced_pdf()
        elif choice == '4':
            delete_enhanced_logs()
        elif choice == '5':
            iface = input("Enter interface (or leave blank for default): ").strip()
            live_monitor(iface if iface else None)
        elif choice == '6':
            file = select_pcap()
            if file:
                print("🗺️ Generating network topology...")
                ip_counter, port_counter, proto_counter, packets_data = optimized_pcap_analysis(file)
                mapper = NetworkMapper()
                topology = mapper.build_network_map(packets_data)
                print(f"📊 Network Topology Summary:")
                print(f"   Devices: {topology['topology_metrics']['total_devices']}")
                print(f"   Connections: {topology['topology_metrics']['total_connections']}")
                print(f"   Internal/External: {topology['topology_metrics']['internal_external_ratio']}")
        elif choice == '7':
            file = select_pcap()
            if file:
                print("🤖 Running ML anomaly detection...")
                ip_counter, port_counter, proto_counter, packets_data = optimized_pcap_analysis(file)
                detector = NetworkAnomalyDetector()
                anomalies = detector.detect_anomalies(packets_data)
                print(f"🔍 ML Results: {len(anomalies)} anomalies detected ({len(anomalies)/len(packets_data)*100:.2f}%)")
                
                # Protocol diversity analysis
                print("🔍 Running protocol diversity analysis...")
                protocol_alerts = analyze_protocol_diversity(proto_counter, packets_data)
                if protocol_alerts:
                    print(f"🚨 Protocol Diversity Alerts: {len(protocol_alerts)}")
                    for alert in protocol_alerts:
                        print(f"   [{alert['severity']}] {alert['message']}")
                
                if anomalies:
                    print("Top anomalies:")
                    for i, idx in enumerate(anomalies[:3]):
                        pkt = packets_data[idx]
                        print(f"  {i+1}. {pkt.get('src')} -> {pkt.get('dst')} ({pkt.get('protocol')})")
        elif choice == '0':
            print("Exiting Enhanced Network Analyzer...")
            break
        else:
            print("❌ Invalid choice.")

# ------------------------
# Simple Dashboard Launcher
# ------------------------
def launch_dashboard_simple():
    """Simple dashboard launcher without complex imports"""
    try:
        if not os.path.exists("enhanced_summary.json"):
            print("❌ enhanced_summary.json not found. Run PCAP analysis first (Option 1).")
            return
        
        print("🚀 Launching Interactive Dashboard...")
        
        # Simple subprocess approach
        import subprocess
        subprocess.run(["python3", "interactive_dashboard.py"])
        
    except Exception as e:
        print(f"❌ Error launching dashboard: {e}")
        print("💡 Make sure interactive_dashboard.py exists in the same directory")

# ------------------------
# Main Execution
# ------------------------
if __name__ == "__main__":
    main()
