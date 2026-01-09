#!/usr/bin/env python3
import pyshark
import json
import time
from collections import defaultdict, deque
from datetime import datetime
import threading
import smtplib
from email.mime.text import MIMEText
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import math

class RealTimeMonitor:
    def __init__(self, interface=None, alert_thresholds=None):
        self.interface = interface or "eth0"
        self.running = False
        self.packet_count = 0
        self.start_time = datetime.now()
        
        # Statistics
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.alert_stats = defaultdict(int)
        
        # Real-time data buffers
        self.packet_rate_buffer = deque(maxlen=60)
        self.throughput_buffer = deque(maxlen=60)
        self.alert_buffer = deque(maxlen=100)
        
        # Alert thresholds
        self.alert_thresholds = alert_thresholds or {
            'packet_rate': 1000,
            'syn_flood': 50,
            'port_scan': 10,
            'large_packet': 1500,
        }
        
        # Protocol diversity monitoring
        self.protocol_alerts_buffer = deque(maxlen=20)
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.running = True
        self.start_time = datetime.now()
        
        print(f"🚀 Starting real-time monitoring on interface: {self.interface}")
        print("📊 Collecting baseline data for 30 seconds...")
        
        # Start background threads
        stats_thread = threading.Thread(target=self._update_display, daemon=True)
        stats_thread.start()
        
        alert_thread = threading.Thread(target=self._check_alerts, daemon=True)
        alert_thread.start()
        
        # Protocol diversity monitoring thread
        protocol_thread = threading.Thread(target=self._check_protocol_diversity, daemon=True)
        protocol_thread.start()
        
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            capture.apply_on_packets(self._process_packet)
            
        except KeyboardInterrupt:
            self.stop_monitoring()
        except Exception as e:
            print(f"❌ Capture error: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring and generate report"""
        self.running = False
        print("\n🛑 Stopping real-time monitoring...")
        self._generate_final_report()
    
    def _process_packet(self, packet):
        """Process individual packet in real-time"""
        if not self.running:
            return
        
        self.packet_count += 1
        current_time = datetime.now()
        
        try:
            # Basic packet information
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                self.ip_stats[src_ip] += 1
                self.ip_stats[dst_ip] += 1
                
                # Protocol statistics
                protocol = getattr(packet, 'highest_layer', 'UNKNOWN')
                self.protocol_stats[protocol] += 1
                
                # Port statistics
                if hasattr(packet, 'tcp'):
                    sport = packet.tcp.srcport
                    dport = packet.tcp.dstport
                    self.port_stats[sport] += 1
                    self.port_stats[dport] += 1
                    
                    # SYN flood detection
                    flags = getattr(packet.tcp, 'flags', '')
                    if 'SYN' in flags and 'ACK' not in flags:
                        self._check_syn_flood(src_ip, current_time)
                
                elif hasattr(packet, 'udp'):
                    sport = packet.udp.srcport
                    dport = packet.udp.dstport
                    self.port_stats[sport] += 1
                    self.port_stats[dport] += 1
                
                # Large packet detection
                packet_size = int(getattr(packet, 'length', 0))
                if packet_size > self.alert_thresholds['large_packet']:
                    self._trigger_alert('LARGE_PACKET', 
                                      f"Large packet detected: {packet_size} bytes from {src_ip}")
            
            # Update rate buffers
            self.packet_rate_buffer.append(current_time)
            self.throughput_buffer.append((current_time, packet_size))
            
            # Check for port scanning
            self._check_port_scan(src_ip, current_time)
            
        except Exception as e:
            pass
    
    def _check_protocol_diversity(self):
        """Background thread for protocol diversity monitoring"""
        while self.running:
            try:
                if sum(self.protocol_stats.values()) > 100:  # Minimum packets for analysis
                    alerts = self._analyze_protocol_diversity()
                    for alert in alerts:
                        self.protocol_alerts_buffer.append(alert)
                        self._trigger_alert(alert['type'], alert['message'])
                
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                print(f"Protocol diversity check error: {e}")
    
    def _analyze_protocol_diversity(self):
    """Analyze protocol distribution for ANY monoculture patterns"""
    alerts = []
    
    if not self.protocol_stats:
        return alerts
    
    total_packets = sum(self.protocol_stats.values())
    if total_packets == 0:
        return alerts
    
    # High-risk protocols
    high_risk_protocols = {
        'DCERPC': 'lateral movement or exploitation',
        'SMB': 'file sharing attacks', 
        'RDP': 'remote desktop brute force',
        'SSH': 'SSH brute force attacks'
    }
    
    # Calculate protocol concentration
    sorted_protocols = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)
    top_protocol, top_count = sorted_protocols[0]
    top_percentage = (top_count / total_packets) * 100
    
    # Alert on ANY protocol monoculture
    if top_percentage > 80.0:
        risk_context = high_risk_protocols.get(top_protocol, "unusual network behavior")
        alerts.append({
            'type': 'PROTOCOL_MONOCULTURE',
            'message': f"Protocol dominance: {top_protocol} {top_percentage:.1f}% - possible {risk_context}",
            'severity': 'HIGH'
        })
    
    # High-risk protocol specific alerts
    for protocol, description in high_risk_protocols.items():
        if protocol in self.protocol_stats and self.protocol_stats[protocol] / total_packets > 0.3:
            alerts.append({
                'type': f'{protocol}_DOMINANCE',
                'message': f"High {protocol} traffic: {(self.protocol_stats[protocol]/total_packets)*100:.1f}% - possible {description}",
                'severity': 'CRITICAL' if protocol in ['DCERPC', 'SMB'] else 'HIGH'
            })
    
    return alerts
    
    def _calculate_protocol_entropy(self):
        """Calculate Shannon entropy of protocol distribution"""
        total = sum(self.protocol_stats.values())
        if total == 0:
            return 0
        
        entropy = 0
        for count in self.protocol_stats.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_syn_flood(self, src_ip, timestamp):
        """Check for SYN flood attacks"""
        key = f"syn_{src_ip}_{timestamp.minute}"
        self.alert_stats[key] += 1
        
        if self.alert_stats[key] > self.alert_thresholds['syn_flood']:
            self._trigger_alert('SYN_FLOOD', 
                              f"Possible SYN flood from {src_ip}: {self.alert_stats[key]} SYN packets")
    
    def _check_port_scan(self, src_ip, timestamp):
        """Check for port scanning activity"""
        key = f"ports_{src_ip}_{timestamp.minute}"
        
        if key not in self.alert_stats:
            self.alert_stats[key] = set()
        
        # Simplified port scan detection
        if len(self.alert_stats[key]) > self.alert_thresholds['port_scan']:
            self._trigger_alert('PORT_SCAN', 
                              f"Possible port scan from {src_ip}: {len(self.alert_stats[key])} unique ports")
    
    def _trigger_alert(self, alert_type, message):
        """Trigger an alert"""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': self._get_alert_severity(alert_type)
        }
        
        self.alert_buffer.append(alert_data)
        print(f"🚨 ALERT [{alert_type}]: {message}")
    
    def _get_alert_severity(self, alert_type):
        """Determine alert severity"""
        severity_map = {
            'SYN_FLOOD': 'HIGH',
            'PORT_SCAN': 'MEDIUM',
            'LARGE_PACKET': 'LOW',
            'HIGH_TRAFFIC': 'MEDIUM',
            'PROTOCOL_MONOCULTURE': 'HIGH',
            'DCERPC_DOMINANCE': 'CRITICAL',
            'LOW_PROTOCOL_ENTROPY': 'MEDIUM'
        }
        return severity_map.get(alert_type, 'LOW')
    
    def _update_display(self):
        """Update real-time display"""
        while self.running:
            try:
                self._display_stats()
                time.sleep(2)
            except Exception as e:
                print(f"Display update error: {e}")
    
    def _display_stats(self):
        """Display current statistics"""
        current_time = datetime.now()
        duration = (current_time - self.start_time).total_seconds()
        
        # Calculate rates
        packets_per_second = self.packet_count / max(duration, 1)
        
        # Protocol diversity metrics
        protocol_entropy = self._calculate_protocol_entropy()
        total_protocols = len(self.protocol_stats)
        
        # Clear screen and display stats
        print("\033[2J\033[H")
        print("="*60)
        print("           REAL-TIME NETWORK MONITOR")
        print("="*60)
        print(f"Duration: {duration:.0f}s | Packets: {self.packet_count:,} | Rate: {packets_per_second:.1f} pps")
        print(f"Protocols: {total_protocols} | Diversity: {protocol_entropy:.2f} entropy")
        print("-"*60)
        
        # Top protocols
        print("\n📊 Top Protocols:")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            percentage = (count / max(self.packet_count, 1)) * 100
            print(f"  {proto}: {count} ({percentage:.1f}%)")
        
        # Top IPs
        print("\n🌐 Top Talkers:")
        for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")
        
        # Recent alerts
        print(f"\n🚨 Recent Alerts ({len(self.alert_buffer)}):")
        for alert in list(self.alert_buffer)[-3:]:
            print(f"  [{alert['severity']}] {alert['message']}")
        
        # Protocol diversity alerts
        if self.protocol_alerts_buffer:
            print(f"\n🔍 Protocol Diversity Alerts ({len(self.protocol_alerts_buffer)}):")
            for alert in list(self.protocol_alerts_buffer)[-2:]:
                print(f"  [{alert['severity']}] {alert['message']}")
        
        print("\n" + "="*60)
        print("Press Ctrl+C to stop monitoring...")
    
    def _check_alerts(self):
        """Background thread for checking alert conditions"""
        while self.running:
            try:
                # Check packet rate
                if len(self.packet_rate_buffer) > 10:
                    recent_packets = [t for t in self.packet_rate_buffer 
                                    if (datetime.now() - t).total_seconds() <= 10]
                    if len(recent_packets) > self.alert_thresholds['packet_rate'] * 10:
                        self._trigger_alert('HIGH_TRAFFIC', 
                                          f"High traffic detected: {len(recent_packets)} packets in 10s")
                
                time.sleep(5)
            except Exception as e:
                print(f"Alert check error: {e}")
    
    def _generate_final_report(self):
        """Generate final monitoring report"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Protocol diversity analysis
        protocol_alerts = self._analyze_protocol_diversity()
        
        report = {
            'monitoring_duration_seconds': duration,
            'total_packets': self.packet_count,
            'average_packet_rate': self.packet_count / duration,
            'protocol_distribution': dict(self.protocol_stats),
            'top_talkers': dict(sorted(self.ip_stats.items(), 
                                     key=lambda x: x[1], reverse=True)[:10]),
            'alerts_triggered': len(self.alert_buffer),
            'alert_details': list(self.alert_buffer),
            'protocol_diversity_alerts': protocol_alerts,
            'protocol_entropy': self._calculate_protocol_entropy()
        }
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"realtime_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Monitoring report saved: {filename}")
        
        # Print protocol diversity summary
        if protocol_alerts:
            print(f"\n🚨 Protocol Diversity Findings:")
            for alert in protocol_alerts:
                print(f"  [{alert['severity']}] {alert['message']}")
        
        self._create_realtime_visualization(report)
    
    def _create_realtime_visualization(self, report):
        """Create visualization from monitoring data"""
        try:
            # Protocol distribution
            protocols = list(report['protocol_distribution'].keys())[:10]
            counts = list(report['protocol_distribution'].values())[:10]
            
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=('Protocol Distribution', 'Top Talkers'),
                specs=[[{"type": "pie"}, {"type": "bar"}]]
            )
            
            fig.add_trace(
                go.Pie(labels=protocols, values=counts, name="Protocols"),
                row=1, col=1
            )
            
            # Top talkers
            talkers = list(report['top_talkers'].keys())[:10]
            talker_counts = list(report['top_talkers'].values())[:10]
            
            fig.add_trace(
                go.Bar(x=talkers, y=talker_counts, name="Top Talkers"),
                row=1, col=2
            )
            
            fig.update_layout(
                height=500,
                title_text=f"Real-time Monitoring Report - {report['total_packets']:,} packets"
            )
            
            fig.show()
            
        except Exception as e:
            print(f"Visualization error: {e}")

# Email notification class (optional)
class AlertNotifier:
    def __init__(self, smtp_server, port, username, password):
        self.smtp_server = smtp_server
        self.port = port
        self.username = username
        self.password = password
    
    def send_alert(self, to_email, subject, message):
        """Send email alert"""
        try:
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = self.username
            msg['To'] = to_email
            
            server = smtplib.SMTP(self.smtp_server, self.port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            print(f"✅ Alert email sent to {to_email}")
        except Exception as e:
            print(f"❌ Failed to send email: {e}")

def main():
    """Main function for real-time monitoring"""
    print("🌐 Real-time Network Monitor")
    print("="*40)
    
    interface = input("Enter network interface (default: eth0): ").strip() or "eth0"
    
    # Custom thresholds
    print("\n🔧 Alert Thresholds (press Enter for defaults):")
    packet_rate = input(f"Packet rate threshold (default: 1000 pps): ")
    syn_flood = input(f"SYN flood threshold (default: 50 SYN/s): ")
    
    thresholds = {
        'packet_rate': int(packet_rate) if packet_rate else 1000,
        'syn_flood': int(syn_flood) if syn_flood else 50,
        'port_scan': 10,
        'large_packet': 1500
    }
    
    monitor = RealTimeMonitor(interface=interface, alert_thresholds=thresholds)
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
    except Exception as e:
        print(f"❌ Monitoring failed: {e}")

if __name__ == "__main__":
    main()
