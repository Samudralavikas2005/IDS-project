#!/usr/bin/env python3
import numpy as np
import pandas as pd
import json
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
import math
warnings.filterwarnings('ignore')

class AdvancedAnomalyDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_selectors = {}
        self.training_data = {}
        
    def load_network_data(self, summary_file="enhanced_summary.json"):
        """Load and prepare network data for ML analysis"""
        try:
            with open(summary_file) as f:
                data = json.load(f)
            return data
        except FileNotFoundError:
            print("❌ Summary file not found")
            return None
    
    def extract_advanced_features(self, network_data):
        """Extract comprehensive features for ML analysis"""
        features = []
        feature_names = []
        
        # Basic traffic features
        total_packets = network_data.get('enhanced_statistics', {}).get('total_packets', 0)
        total_bytes = network_data.get('enhanced_statistics', {}).get('total_bytes', 0)
        
        features.extend([total_packets, total_bytes])
        feature_names.extend(['total_packets', 'total_bytes'])
        
        # Protocol diversity features
        protocol_dist = network_data.get('protocol_distribution', {})
        protocol_count = len(protocol_dist)
        protocol_entropy = self._calculate_entropy(list(protocol_dist.values()))
        
        features.extend([protocol_count, protocol_entropy])
        feature_names.extend(['protocol_count', 'protocol_entropy'])
        
        # Protocol concentration (NEW)
        if protocol_dist:
            top_protocol_pct = max(protocol_dist.values()) / sum(protocol_dist.values())
            features.append(top_protocol_pct)
            feature_names.append('top_protocol_concentration')
            
            # DCERPC specific indicator
            dcerpc_pct = protocol_dist.get('DCERPC', 0) / sum(protocol_dist.values())
            features.append(dcerpc_pct)
            feature_names.append('dcerpc_concentration')
        else:
            features.extend([0, 0])
            feature_names.extend(['top_protocol_concentration', 'dcerpc_concentration'])
        
        # Port statistics
        top_ports = network_data.get('top_ports', [])
        unique_ports = len(top_ports)
        port_entropy = self._calculate_entropy([count for _, count in top_ports])
        
        features.extend([unique_ports, port_entropy])
        feature_names.extend(['unique_ports', 'port_entropy'])
        
        # Traffic concentration
        top_talkers = network_data.get('top_talkers', [])
        if top_talkers:
            talker_counts = [count for _, count in top_talkers]
            concentration = sum(talker_counts[:3]) / sum(talker_counts) if sum(talker_counts) > 0 else 0
        else:
            concentration = 0
        
        features.append(concentration)
        feature_names.append('traffic_concentration')
        
        # Packet size statistics
        size_stats = network_data.get('enhanced_statistics', {}).get('packet_size_stats', {})
        if size_stats:
            features.extend([
                size_stats.get('mean', 0),
                size_stats.get('std', 0),
                size_stats.get('max', 0) / max(size_stats.get('mean', 1), 1)
            ])
            feature_names.extend(['avg_packet_size', 'packet_size_std', 'size_anomaly_ratio'])
        else:
            features.extend([0, 0, 0])
            feature_names.extend(['avg_packet_size', 'packet_size_std', 'size_anomaly_ratio'])
        
        # Network topology features
        topology = network_data.get('network_topology', {})
        topology_metrics = topology.get('topology_metrics', {})
        features.extend([
            topology_metrics.get('total_devices', 0),
            topology_metrics.get('total_connections', 0),
            topology_metrics.get('connection_density', 0)
        ])
        feature_names.extend(['device_count', 'connection_count', 'connection_density'])
        
        return np.array(features).reshape(1, -1), feature_names
    
    def _calculate_entropy(self, values):
        """Calculate entropy of a distribution"""
        if not values or sum(values) == 0:
            return 0
        
        probabilities = np.array(values) / sum(values)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def train_isolation_forest(self, features, feature_names, contamination=0.1):
        """Train Isolation Forest model"""
        model_name = "isolation_forest"
        
        # Scale features
        self.scalers[model_name] = StandardScaler()
        features_scaled = self.scalers[model_name].fit_transform(features)
        
        # Train model
        self.models[model_name] = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        if features.shape[0] > 1:
            self.models[model_name].fit(features_scaled)
        else:
            print("⚠️ Single sample provided. Model needs more data for proper training.")
        
        self.feature_names = feature_names
        return self.models[model_name]
    
    def detect_anomalies(self, features):
        """Detect anomalies using trained models"""
        results = {}
        
        for model_name, model in self.models.items():
            if model_name in self.scalers:
                features_scaled = self.scalers[model_name].transform(features)
                predictions = model.predict(features_scaled)
                anomaly_scores = model.decision_function(features_scaled)
                
                results[model_name] = {
                    'predictions': predictions,
                    'anomaly_scores': anomaly_scores,
                    'is_anomaly': predictions == -1
                }
        
        return results
    
    def cluster_analysis(self, multiple_samples):
        """Perform cluster analysis on multiple network captures"""
        if len(multiple_samples) < 2:
            print("❌ Need at least 2 samples for clustering")
            return None
        
        feature_matrix = np.vstack([sample for sample in multiple_samples])
        
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(feature_matrix)
        
        clustering = DBSCAN(eps=0.5, min_samples=2).fit(features_scaled)
        
        return {
            'labels': clustering.labels_,
            'n_clusters': len(set(clustering.labels_)) - (1 if -1 in clustering.labels_ else 0),
            'outliers': np.sum(clustering.labels_ == -1)
        }
    
    def feature_importance_analysis(self, features, feature_names):
        """Analyze feature importance for anomaly detection"""
        synthetic_labels = np.random.randint(0, 2, features.shape[0])
        
        selector = SelectKBest(score_func=f_classif, k='all')
        selector.fit(features, synthetic_labels)
        
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'score': selector.scores_,
            'p_value': selector.pvalues_
        }).sort_values('score', ascending=False)
        
        return importance_df
    
    def create_ml_report(self, network_data, anomaly_results):
        """Create comprehensive ML analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'network_summary': {
                'total_packets': network_data.get('enhanced_statistics', {}).get('total_packets', 0),
                'total_devices': network_data.get('network_topology', {}).get('topology_metrics', {}).get('total_devices', 0),
                'protocols_detected': len(network_data.get('protocol_distribution', {}))
            },
            'ml_analysis': anomaly_results,
            'risk_assessment': self._assess_risk(anomaly_results),
            'recommendations': self._generate_recommendations(anomaly_results, network_data)
        }
        
        return report
    
    def _assess_risk(self, anomaly_results):
        """Assess overall risk based on ML results"""
        risk_score = 0
        factors = []
        
        for model_name, result in anomaly_results.items():
            if np.any(result['is_anomaly']):
                risk_score += 0.7
                factors.append(f"{model_name} detected anomalies")
            
            avg_score = np.mean(result['anomaly_scores'])
            if avg_score < -0.1:
                risk_score += 0.3
                factors.append(f"High anomaly score in {model_name}")
        
        risk_level = "LOW"
        if risk_score > 1.0:
            risk_level = "HIGH"
        elif risk_score > 0.5:
            risk_level = "MEDIUM"
        
        return {
            'risk_score': min(risk_score, 1.0),
            'risk_level': risk_level,
            'factors': factors
        }
    
    def _generate_recommendations(self, anomaly_results, network_data):
        """Generate security recommendations"""
        recommendations = []
        
        # Protocol diversity checks
        protocol_dist = network_data.get('protocol_distribution', {})
        if protocol_dist:
            top_protocol_pct = max(protocol_dist.values()) / sum(protocol_dist.values())
            if top_protocol_pct > 0.8:
                recommendations.append(
                    "High protocol concentration detected - investigate for C2 communication"
                )
            
            if 'DCERPC' in protocol_dist and protocol_dist['DCERPC'] / sum(protocol_dist.values()) > 0.3:
                recommendations.append(
                    "High DCERPC traffic - check for lateral movement attempts"
                )
        
        # ML-based recommendations
        if any(result['is_anomaly'].any() for result in anomaly_results.values()):
            recommendations.append(
                "ML models detected anomalous patterns - review detailed anomaly report"
            )
        
        # Add general recommendations
        recommendations.extend([
            "Regularly update baseline models with new network data",
            "Implement automated alerting for high-risk anomalies",
            "Correlate ML findings with traditional security monitoring"
        ])
        
        return recommendations
    
    def visualize_ml_results(self, features, anomaly_results, feature_names):
        """Visualize ML analysis results"""
        if features.shape[1] < 2:
            print("❌ Need at least 2 features for visualization")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Feature distribution
        feature_df = pd.DataFrame(features, columns=feature_names)
        feature_df.iloc[:, :4].boxplot(ax=axes[0, 0])
        axes[0, 0].set_title('Feature Distributions')
        axes[0, 0].tick_params(axis='x', rotation=45)
        
        # Anomaly scores
        for model_name, result in anomaly_results.items():
            axes[0, 1].hist(result['anomaly_scores'], alpha=0.7, label=model_name)
        axes[0, 1].set_title('Anomaly Score Distribution')
        axes[0, 1].legend()
        
        # Feature correlation
        if features.shape[0] > 1:
            corr_matrix = np.corrcoef(features.T)
            sns.heatmap(corr_matrix, annot=True, fmt='.2f', 
                       xticklabels=feature_names[:corr_matrix.shape[0]], 
                       yticklabels=feature_names[:corr_matrix.shape[0]], 
                       ax=axes[1, 0])
            axes[1, 0].set_title('Feature Correlation Matrix')
        
        # Risk assessment
        risk_data = self._assess_risk(anomaly_results)
        risk_levels = ['LOW', 'MEDIUM', 'HIGH']
        risk_counts = [0, 0, 0]
        risk_index = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
        risk_counts[risk_index[risk_data['risk_level']]] = 1
        
        axes[1, 1].bar(risk_levels, risk_counts, color=['green', 'orange', 'red'])
        axes[1, 1].set_title('Risk Assessment')
        axes[1, 1].set_ylabel('Level')
        
        plt.tight_layout()
        plt.show()

def demo_ml_analysis():
    """Demonstrate ML anomaly detection"""
    print("🤖 Advanced ML Anomaly Detection Demo")
    print("="*50)
    
    detector = AdvancedAnomalyDetector()
    
    # Load sample data
    network_data = detector.load_network_data()
    if not network_data:
        print("❌ No data available for analysis")
        return
    
    # Extract features
    features, feature_names = detector.extract_advanced_features(network_data)
    print(f"📊 Extracted {len(feature_names)} features")
    print("Features:", feature_names)
    
    # For demo, create multiple samples by adding noise
    multiple_samples = [features]
    for i in range(5):
        noisy_sample = features + np.random.normal(0, 0.1, features.shape)
        multiple_samples.append(noisy_sample)
    
    feature_matrix = np.vstack(multiple_samples)
    
    # Train model
    print("🔄 Training ML models...")
    detector.train_isolation_forest(feature_matrix, feature_names)
    
    # Detect anomalies
    print("🔍 Running anomaly detection...")
    anomaly_results = detector.detect_anomalies(feature_matrix)
    
    # Feature importance
    print("📈 Analyzing feature importance...")
    importance_df = detector.feature_importance_analysis(feature_matrix, feature_names)
    print("\nTop 5 most important features:")
    print(importance_df.head())
    
    # Generate report
    report = detector.create_ml_report(network_data, anomaly_results)
    
    print("\n" + "="*50)
    print("ML ANALYSIS REPORT")
    print("="*50)
    print(f"Risk Level: {report['risk_assessment']['risk_level']}")
    print(f"Risk Score: {report['risk_assessment']['risk_score']:.2f}")
    print("\nKey Findings:")
    for factor in report['risk_assessment']['factors']:
        print(f"  • {factor}")
    
    print("\nRecommendations:")
    for rec in report['recommendations'][:3]:
        print(f"  • {rec}")
    
    # Visualization
    print("\n📊 Generating visualizations...")
    detector.visualize_ml_results(feature_matrix, anomaly_results, feature_names)
    
    # Save detailed report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"ml_analysis_report_{timestamp}.json"
    
    with open(report_file, 'w') as f:
        serializable_report = json.loads(json.dumps(report, default=lambda x: x.tolist() if hasattr(x, 'tolist') else str(x)))
        json.dump(serializable_report, f, indent=2)
    
    print(f"✅ ML analysis report saved: {report_file}")

if __name__ == "__main__":
    demo_ml_analysis()
