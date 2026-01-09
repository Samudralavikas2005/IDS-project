#!/usr/bin/env python3
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import json
import numpy as np
from datetime import datetime
import math

class InteractiveNetworkDashboard:
    def __init__(self, summary_file="enhanced_summary.json"):
        self.summary_file = summary_file
        self.load_summary()
    
    def load_summary(self):
        """Load the enhanced summary data"""
        try:
            with open(self.summary_file) as f:
                self.summary = json.load(f)
            print("✅ Loaded enhanced summary data")
        except FileNotFoundError:
            print("❌ enhanced_summary.json not found. Run analysis first.")
            self.summary = None
    
    def create_comprehensive_dashboard(self):
        """Create comprehensive interactive dashboard"""
        if not self.summary:
            return
        
        self.create_main_overview()
        self.create_network_topology_view()
        self.create_anomaly_analysis_view()
        self.create_performance_metrics_view()
        self.create_protocol_diversity_view()
    
    def create_main_overview(self):
        """Main overview with key metrics"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Top Talkers', 'Protocol Distribution', 
                          'Port Activity', 'Packet Size Statistics'),
            specs=[[{"type": "bar"}, {"type": "pie"}],
                   [{"type": "bar"}, {"type": "bar"}]],
            vertical_spacing=0.1,
            horizontal_spacing=0.1
        )
        
        # Top Talkers
        if self.summary['top_talkers']:
            ips, counts = zip(*self.summary['top_talkers'])
            fig.add_trace(
                go.Bar(x=ips, y=counts, name="Top Talkers", 
                      marker_color='skyblue', hovertemplate='<b>%{x}</b><br>Packets: %{y}'),
                row=1, col=1
            )
        
        # Protocol Distribution
        if self.summary['protocol_distribution']:
            protocols = list(self.summary['protocol_distribution'].keys())
            counts = list(self.summary['protocol_distribution'].values())
            fig.add_trace(
                go.Pie(labels=protocols, values=counts, name="Protocols",
                      hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}'),
                row=1, col=2
            )
        
        # Top Ports
        if self.summary['top_ports']:
            ports, counts = zip(*self.summary['top_ports'])
            fig.add_trace(
                go.Bar(x=ports, y=counts, name="Top Ports",
                      marker_color='lightcoral', hovertemplate='<b>Port %{x}</b><br>Count: %{y}'),
                row=2, col=1
            )
        
        # Packet Size Statistics
        stats = self.summary.get('enhanced_statistics', {}).get('packet_size_stats', {})
        if stats:
            sizes = [stats['min'], stats['percentiles']['25'], 
                    stats['percentiles']['50'], stats['percentiles']['75'], stats['max']]
            labels = ['Min', '25th %', 'Median', '75th %', 'Max']
            fig.add_trace(
                go.Bar(x=labels, y=sizes, name="Packet Sizes",
                      marker_color='lightgreen', 
                      hovertemplate='<b>%{x}</b><br>Size: %{y} bytes'),
                row=2, col=2
            )
        
        fig.update_layout(
            height=800,
            title_text="Network Analysis - Main Overview",
            showlegend=False
        )
        
        fig.show()
    
    def create_protocol_diversity_view(self):
        """Protocol diversity and concentration analysis"""
        protocol_data = self.summary.get('protocol_distribution', {})
        protocol_alerts = self.summary.get('protocol_diversity_alerts', [])
        
        if not protocol_data:
            print("⚠️ No protocol data available")
            return
        
        total_packets = sum(protocol_data.values())
        top_protocol = max(protocol_data, key=protocol_data.get)
        top_percentage = (protocol_data[top_protocol] / total_packets) * 100
        
        # Calculate protocol entropy
        entropy = self._calculate_entropy(list(protocol_data.values()))
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=('Protocol Concentration', 'Diversity Metrics'),
            specs=[[{"type": "indicator"}, {"type": "bar"}]]
        )
        
        # Protocol concentration gauge
        fig.add_trace(
            go.Indicator(
                mode = "gauge+number+delta",
                value = top_percentage,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': f"Top Protocol: {top_protocol}"},
                gauge = {
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "lightgray"},
                        {'range': [50, 80], 'color': "yellow"},
                        {'range': [80, 100], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 80
                    }
                }
            ),
            row=1, col=1
        )
        
        # Diversity metrics
        metrics = ['Protocol Entropy', 'Unique Protocols', 'Top Protocol %']
        values = [entropy, len(protocol_data), top_percentage]
        
        fig.add_trace(
            go.Bar(x=metrics, y=values, marker_color=['blue', 'green', 'red']),
            row=1, col=2
        )
        
        fig.update_layout(
            height=400,
            title_text="Protocol Diversity Analysis"
        )
        
        fig.show()
        
        # Display alerts
        if protocol_alerts:
            print(f"\n🚨 Protocol Diversity Alerts ({len(protocol_alerts)}):")
            for alert in protocol_alerts:
                print(f"   [{alert.get('severity', 'UNKNOWN')}] {alert.get('message', '')}")
    
    def _calculate_entropy(self, values):
        """Calculate Shannon entropy"""
        if not values or sum(values) == 0:
            return 0
        
        probabilities = np.array(values) / sum(values)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def create_network_topology_view(self):
        """Network topology visualization"""
        topology = self.summary.get('network_topology', {})
        if not topology.get('devices'):
            print("⚠️ No topology data available")
            return
        
        # Create node and edge lists for network graph
        nodes = []
        edges = []
        node_ids = {}
        
        # Assign IDs to nodes
        for i, (ip, info) in enumerate(topology['devices'].items()):
            node_ids[ip] = i
            nodes.append({
                'id': i,
                'label': ip,
                'title': f"IP: {ip}<br>Location: {info.get('geo', 'Unknown')}<br>Packets: {info.get('packet_count', 0)}",
                'value': info.get('packet_count', 1),
                'group': 1 if ip.startswith(('10.', '192.168.', '172.')) else 2
            })
        
        # Create edges
        connection_counts = {}
        for conn in topology.get('connections', []):
            src = conn['source']
            dst = conn['target']
            key = (src, dst)
            connection_counts[key] = connection_counts.get(key, 0) + 1
        
        for (src, dst), count in connection_counts.items():
            if src in node_ids and dst in node_ids:
                edges.append({
                    'from': node_ids[src],
                    'to': node_ids[dst],
                    'value': count,
                    'title': f"{src} → {dst}<br>Connections: {count}"
                })
        
        # Create network graph
        fig = go.Figure()
        
        # Add edges
        edge_x = []
        edge_y = []
        for edge in edges:
            src_node = nodes[edge['from']]
            dst_node = nodes[edge['to']]
            edge_x.extend([src_node['id'], dst_node['id'], None])
            edge_y.extend([src_node['value'], dst_node['value'], None])
        
        fig.add_trace(go.Scatter(x=edge_x, y=edge_y,
                               line=dict(width=0.5, color='#888'),
                               hoverinfo='none',
                               mode='lines'))
        
        # Add nodes
        node_x = [node['id'] for node in nodes]
        node_y = [node['value'] for node in nodes]
        node_text = [node['label'] for node in nodes]
        
        fig.add_trace(go.Scatter(x=node_x, y=node_y,
                               mode='markers+text',
                               hoverinfo='text',
                               text=node_text,
                               textposition="middle center",
                               marker=dict(
                                   size=20,
                                   color=[node['group'] for node in nodes],
                                   colorscale='Viridis',
                                   line=dict(width=2))))
        
        fig.update_layout(
            title="Network Topology",
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[ dict(
                text="Network device relationships",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.005, y=-0.002 ) ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
        
        fig.show()
        
        # Also show topology metrics
        self.create_topology_metrics_view(topology)
    
    def create_topology_metrics_view(self, topology):
        """Display topology metrics"""
        metrics = topology.get('topology_metrics', {})
        
        fig = go.Figure()
        
        metrics_names = list(metrics.keys())
        metrics_values = [metrics[name] for name in metrics_names 
                         if isinstance(metrics[name], (int, float))]
        metrics_names_display = [name.replace('_', ' ').title() 
                                for name in metrics_names 
                                if isinstance(metrics[name], (int, float))]
        
        fig.add_trace(go.Bar(x=metrics_names_display, y=metrics_values,
                            marker_color='lightblue',
                            text=metrics_values,
                            textposition='auto'))
        
        fig.update_layout(
            title="Network Topology Metrics",
            xaxis_title="Metrics",
            yaxis_title="Count"
        )
        
        fig.show()
    
    def create_anomaly_analysis_view(self):
        """ML Anomaly detection results"""
        anomaly_data = self.summary.get('anomaly_detection', {})
        total_packets = self.summary.get('enhanced_statistics', {}).get('total_packets', 1)
        anomalies = anomaly_data.get('anomalous_packets', [])
        
        if not anomalies:
            print("⚠️ No anomaly data available")
            return
        
        # Anomaly overview
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=('Anomaly Distribution', 'Anomaly Protocols'),
            specs=[[{"type": "pie"}, {"type": "bar"}]]
        )
        
        # Pie chart: Normal vs Anomalous
        normal_count = total_packets - len(anomalies)
        fig.add_trace(
            go.Pie(labels=['Normal', 'Anomalous'], 
                  values=[normal_count, len(anomalies)],
                  hole=0.3),
            row=1, col=1
        )
        
        # Bar chart: Anomalies by protocol
        proto_counter = {}
        for anomaly in anomalies:
            proto = anomaly.get('protocol', 'UNKNOWN')
            proto_counter[proto] = proto_counter.get(proto, 0) + 1
        
        if proto_counter:
            fig.add_trace(
                go.Bar(x=list(proto_counter.keys()), 
                      y=list(proto_counter.values()),
                      marker_color='red'),
                row=1, col=2
            )
        
        fig.update_layout(height=400, title_text="ML Anomaly Detection Results")
        fig.show()
        
        # Show top anomalies table
        print("\n🔍 Top Anomalous Connections:")
        print("-" * 60)
        for i, anomaly in enumerate(anomalies[:10]):
            print(f"{i+1}. {anomaly.get('src', '?')}:{anomaly.get('sport', '?')} → "
                  f"{anomaly.get('dst', '?')}:{anomaly.get('dport', '?')} "
                  f"({anomaly.get('protocol', '?')}) - {anomaly.get('length', 0)} bytes")
    
    def create_performance_metrics_view(self):
        """Performance and throughput metrics"""
        stats = self.summary.get('enhanced_statistics', {})
        throughput_data = stats.get('throughput_analysis', {}).get('throughput_timeline', [])
        
        if not throughput_data:
            print("⚠️ No throughput data available")
            return
        
        # Throughput over time
        times = [item['time'] for item in throughput_data]
        bytes_data = [item['bytes'] for item in throughput_data]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(x=times, y=bytes_data,
                               mode='lines+markers',
                               name='Throughput',
                               line=dict(width=2),
                               marker=dict(size=6)))
        
        fig.update_layout(
            title="Network Throughput Over Time",
            xaxis_title="Time",
            yaxis_title="Bytes per Minute",
            hovermode='x unified'
        )
        
        fig.show()
        
        # Protocol performance
        protocol_stats = stats.get('protocol_stats', {})
        if protocol_stats:
            protocols = list(protocol_stats.keys())
            avg_sizes = [protocol_stats[proto].get('avg_size', 0) for proto in protocols]
            total_bytes = [protocol_stats[proto].get('total_bytes', 0) for proto in protocols]
            
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=('Average Packet Size by Protocol', 'Total Bytes by Protocol')
            )
            
            fig.add_trace(
                go.Bar(x=protocols, y=avg_sizes, name="Avg Size"),
                row=1, col=1
            )
            
            fig.add_trace(
                go.Bar(x=protocols, y=total_bytes, name="Total Bytes"),
                row=1, col=2
            )
            
            fig.update_layout(height=400, title_text="Protocol Performance Metrics")
            fig.show()
    
    def export_dashboard_data(self, filename="dashboard_export.html"):
        """Export all dashboard views to HTML"""
        if not self.summary:
            return
        
        with open(filename, 'w') as f:
            f.write("""
            <html>
            <head>
                <title>Network Analysis Dashboard</title>
                <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; }
                    .metrics { display: flex; justify-content: space-around; flex-wrap: wrap; }
                    .metric-card { background: #f5f5f5; padding: 15px; margin: 10px; border-radius: 5px; min-width: 200px; }
                    .alert { background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }
                    .warning { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }
                </style>
            </head>
            <body>
                <h1>Network Analysis Dashboard</h1>
                <div class="metrics">
            """)
            
            # Key metrics
            total_packets = self.summary.get('enhanced_statistics', {}).get('total_packets', 0)
            total_bytes = self.summary.get('enhanced_statistics', {}).get('total_bytes', 0)
            anomalies = self.summary.get('anomaly_detection', {}).get('total_anomalies', 0)
            devices = self.summary.get('network_topology', {}).get('topology_metrics', {}).get('total_devices', 0)
            protocol_alerts = len(self.summary.get('protocol_diversity_alerts', []))
            
            f.write(f"""
                <div class="metric-card">
                    <h3>Total Packets</h3>
                    <p style="font-size: 24px; color: #333;">{total_packets:,}</p>
                </div>
                <div class="metric-card">
                    <h3>Total Bytes</h3>
                    <p style="font-size: 24px; color: #333;">{total_bytes:,}</p>
                </div>
                <div class="metric-card">
                    <h3>Anomalies</h3>
                    <p style="font-size: 24px; color: #e74c3c;">{anomalies}</p>
                </div>
                <div class="metric-card">
                    <h3>Devices</h3>
                    <p style="font-size: 24px; color: #333;">{devices}</p>
                </div>
                <div class="metric-card">
                    <h3>Protocol Alerts</h3>
                    <p style="font-size: 24px; color: #f39c12;">{protocol_alerts}</p>
                </div>
            """)
            
            # Protocol diversity alerts
            protocol_alerts_data = self.summary.get('protocol_diversity_alerts', [])
            if protocol_alerts_data:
                f.write('</div><div class="section"><h2>Protocol Diversity Alerts</h2>')
                for alert in protocol_alerts_data:
                    alert_class = 'alert' if alert.get('severity') in ['HIGH', 'CRITICAL'] else 'warning'
                    f.write(f"""
                    <div class="{alert_class}">
                        <strong>[{alert.get('severity', 'UNKNOWN')}]</strong> {alert.get('message', '')}
                    </div>
                    """)
            
            f.write("</div></body></html>")
        
        print(f"✅ Dashboard data exported to {filename}")

def main():
    """Main function to run the interactive dashboard"""
    dashboard = InteractiveNetworkDashboard()
    
    while True:
        print("\n" + "="*50)
        print("      INTERACTIVE NETWORK DASHBOARD")
        print("="*50)
        print("1. Show Main Overview")
        print("2. Show Network Topology")
        print("3. Show Anomaly Analysis")
        print("4. Show Performance Metrics")
        print("5. Show Protocol Diversity Analysis")
        print("6. Create Comprehensive Dashboard")
        print("7. Export Dashboard Data")
        print("0. Back to Main Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == '1':
            dashboard.create_main_overview()
        elif choice == '2':
            dashboard.create_network_topology_view()
        elif choice == '3':
            dashboard.create_anomaly_analysis_view()
        elif choice == '4':
            dashboard.create_performance_metrics_view()
        elif choice == '5':
            dashboard.create_protocol_diversity_view()
        elif choice == '6':
            dashboard.create_comprehensive_dashboard()
        elif choice == '7':
            dashboard.export_dashboard_data()
        elif choice == '0':
            break
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main()
