#!/usr/bin/env python3
"""
NET-PATROL-X Real-Time Network Monitor
Captures live network traffic and analyzes encrypted flows
"""

import time
import threading
import queue
import psutil
import socket
import struct
import subprocess
import json
from datetime import datetime
from collections import defaultdict, deque
import numpy as np
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls import TLS
import joblib

class NetworkFlow:
    """Represents a network flow for analysis"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
        self.start_time = time.time()
        self.last_seen = time.time()
        
        # Flow characteristics
        self.packet_count = 0
        self.total_bytes = 0
        self.packet_sizes = []
        self.interarrival_times = []
        self.last_packet_time = None
        
        # TLS-specific features
        self.tls_version = None
        self.cipher_suite = None
        self.sni = None
        self.session_resumption = False

class RealTimeNetworkMonitor:
    """Real-time network monitoring and analysis"""
    
    def __init__(self, model_path="./out/global_model.pkl", interface=None):
        self.model_path = model_path
        self.interface = interface or self._get_default_interface()
        self.model = self._load_model()
        self.flows = {}  # Active flows
        self.packet_queue = queue.Queue()
        self.analysis_queue = queue.Queue()
        self.running = False
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'analyzed_flows': 0,
            'threats_detected': 0,
            'start_time': time.time()
        }
        
        # Configuration
        self.flow_timeout = 60  # seconds
        self.min_packets_for_analysis = 10
        self.analysis_interval = 5  # seconds
        
    def _get_default_interface(self):
        """Get the default network interface"""
        try:
            # Get the interface used for default route
            result = subprocess.run(['route', 'get', 'default'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    return line.split(':')[1].strip()
        except:
            pass
        
        # Fallback to first active interface
        interfaces = psutil.net_if_addrs()
        for interface_name in interfaces:
            if interface_name.startswith('en') or interface_name.startswith('eth'):
                return interface_name
        
        return 'en0'  # Default fallback
    
    def _load_model(self):
        """Load the trained model"""
        try:
            model_data = joblib.load(self.model_path)
            print(f"✅ Loaded model from {self.model_path}")
            return model_data
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return None
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        if not self.running:
            return
            
        try:
            self.packet_queue.put(packet)
            self.stats['total_packets'] += 1
        except Exception as e:
            print(f"Packet handling error: {e}")
    
    def _extract_flow_features(self, flow):
        """Extract features from a network flow"""
        if len(flow.packet_sizes) < self.min_packets_for_analysis:
            return None
            
        # Basic flow features
        packet_count = len(flow.packet_sizes)
        avg_pkt_size = np.mean(flow.packet_sizes) if flow.packet_sizes else 0
        
        # Calculate entropy of packet sizes
        if len(flow.packet_sizes) > 1:
            entropy = self._calculate_entropy(flow.packet_sizes)
        else:
            entropy = 0
            
        # TLS version (simplified - would need proper TLS parsing)
        tls_version = flow.tls_version or 1.3
        
        # Cipher rank (simplified)
        cipher_rank = flow.cipher_suite or 25
        
        # Inter-arrival times
        if len(flow.interarrival_times) > 0:
            interarrival_mean = np.mean(flow.interarrival_times)
        else:
            interarrival_mean = 0.05
            
        # SNI entropy (simplified)
        sni_entropy = 4.0  # Would need to analyze SNI patterns
        
        # Session resumption
        session_resumption = 1 if flow.session_resumption else 0
        
        return {
            'packet_count': packet_count,
            'avg_pkt_size': avg_pkt_size,
            'entropy': entropy,
            'tls_version': tls_version,
            'cipher_rank': cipher_rank,
            'interarrival_mean': interarrival_mean,
            'sni_entropy': sni_entropy,
            'session_resumption': session_resumption
        }
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
            
        # Discretize data into bins
        bins = np.histogram(data, bins=10)[0]
        probabilities = bins / np.sum(bins)
        probabilities = probabilities[probabilities > 0]  # Remove zeros
        
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _analyze_flow(self, flow):
        """Analyze a flow using the trained model"""
        if not self.model:
            return None
            
        features = self._extract_flow_features(flow)
        if not features:
            return None
            
        try:
            # Prepare features in the same order as training
            feature_names = ["packet_count", "avg_pkt_size", "entropy", "tls_version", 
                           "cipher_rank", "interarrival_mean", "sni_entropy", "session_resumption"]
            
            x_raw = [features.get(f, 0.0) for f in feature_names]
            Xs = self.model['scaler'].transform([x_raw])[0]
            
            # Make prediction
            coef = np.array(self.model['coef'])
            intercept = float(self.model['intercept'])
            logit = Xs.dot(coef) + intercept
            probability = 1 / (1 + np.exp(-logit))
            
            # Calculate feature contributions
            contributions = Xs * coef
            feature_contributions = list(zip(feature_names, contributions))
            feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            
            return {
                'flow_id': f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}",
                'probability': float(probability),
                'features': features,
                'top_contributors': feature_contributions[:3],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Analysis error: {e}")
            return None
    
    def _packet_processor(self):
        """Process packets from the queue"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Packet processing error: {e}")
    
    def _process_packet(self, packet):
        """Process individual packet and update flows"""
        try:
            # Extract basic packet information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = 'TCP'
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = 'UDP'
                else:
                    return
                
                # Create flow key (bidirectional)
                flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                
                if flow_key not in self.flows:
                    self.flows[flow_key] = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol)
                
                flow = self.flows[flow_key]
                
                # Update flow statistics
                flow.packet_count += 1
                flow.total_bytes += len(packet)
                flow.packet_sizes.append(len(packet))
                flow.last_seen = time.time()
                
                # Calculate inter-arrival time
                current_time = time.time()
                if flow.last_packet_time:
                    interarrival = current_time - flow.last_packet_time
                    flow.interarrival_times.append(interarrival)
                flow.last_packet_time = current_time
                
                # Basic TLS detection (port 443)
                if dst_port == 443 or src_port == 443:
                    flow.tls_version = 1.3  # Simplified
                    flow.cipher_rank = 30   # Simplified
                
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    def _flow_analyzer(self):
        """Analyze flows and detect threats"""
        while self.running:
            try:
                time.sleep(self.analysis_interval)
                
                current_time = time.time()
                flows_to_analyze = []
                flows_to_remove = []
                
                # Find flows ready for analysis or expired
                for flow_key, flow in self.flows.items():
                    if (current_time - flow.last_seen) > self.flow_timeout:
                        flows_to_remove.append(flow_key)
                    elif flow.packet_count >= self.min_packets_for_analysis:
                        flows_to_analyze.append(flow)
                
                # Remove expired flows
                for flow_key in flows_to_remove:
                    del self.flows[flow_key]
                
                # Analyze flows
                for flow in flows_to_analyze:
                    result = self._analyze_flow(flow)
                    if result:
                        self.stats['analyzed_flows'] += 1
                        
                        # Check for threats
                        if result['probability'] > 0.5:
                            self.stats['threats_detected'] += 1
                            threat_level = "HIGH" if result['probability'] > 0.7 else "MEDIUM"
                            
                            print(f"\n🚨 THREAT DETECTED [{threat_level}]")
                            print(f"   Flow: {result['flow_id']}")
                            print(f"   Probability: {result['probability']:.3f}")
                            print(f"   Top Contributors: {result['top_contributors']}")
                            print(f"   Time: {result['timestamp']}")
                            
                            # Remove analyzed flow
                            for flow_key, f in list(self.flows.items()):
                                if f == flow:
                                    del self.flows[flow_key]
                                    break
                        
            except Exception as e:
                print(f"Flow analysis error: {e}")
    
    def _stats_reporter(self):
        """Report statistics periodically"""
        while self.running:
            try:
                time.sleep(30)  # Report every 30 seconds
                
                runtime = time.time() - self.stats['start_time']
                print(f"\n📊 NET-PATROL-X Statistics (Runtime: {runtime:.0f}s)")
                print(f"   Total Packets: {self.stats['total_packets']}")
                print(f"   Active Flows: {len(self.flows)}")
                print(f"   Analyzed Flows: {self.stats['analyzed_flows']}")
                print(f"   Threats Detected: {self.stats['threats_detected']}")
                print(f"   Interface: {self.interface}")
                
            except Exception as e:
                print(f"Stats reporting error: {e}")
    
    def start_monitoring(self):
        """Start real-time network monitoring"""
        if not self.model:
            print("❌ Cannot start monitoring: Model not loaded")
            return False
            
        print(f"🚀 Starting NET-PATROL-X Real-Time Monitor")
        print(f"   Interface: {self.interface}")
        print(f"   Model: {self.model_path}")
        print(f"   Flow Timeout: {self.flow_timeout}s")
        print(f"   Min Packets: {self.min_packets_for_analysis}")
        print("=" * 60)
        
        self.running = True
        
        # Start worker threads
        packet_thread = threading.Thread(target=self._packet_processor)
        analyzer_thread = threading.Thread(target=self._flow_analyzer)
        stats_thread = threading.Thread(target=self._stats_reporter)
        
        packet_thread.daemon = True
        analyzer_thread.daemon = True
        stats_thread.daemon = True
        
        packet_thread.start()
        analyzer_thread.start()
        stats_thread.start()
        
        try:
            # Start packet capture
            sniff(iface=self.interface, prn=self._packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n🛑 Stopping NET-PATROL-X Monitor...")
            self.stop_monitoring()
        except Exception as e:
            print(f"❌ Monitoring error: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        print("✅ NET-PATROL-X Monitor stopped")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NET-PATROL-X Real-Time Network Monitor")
    parser.add_argument("--interface", help="Network interface to monitor")
    parser.add_argument("--model", default="./out/global_model.pkl", help="Path to trained model")
    parser.add_argument("--timeout", type=int, default=60, help="Flow timeout in seconds")
    parser.add_argument("--min-packets", type=int, default=10, help="Minimum packets for analysis")
    
    args = parser.parse_args()
    
    # Check if running as root (required for packet capture)
    if os.geteuid() != 0:
        print("❌ This script requires root privileges for packet capture")
        print("   Please run with: sudo python network_monitor.py")
        return
    
    # Create and start monitor
    monitor = RealTimeNetworkMonitor(
        model_path=args.model,
        interface=args.interface
    )
    
    monitor.flow_timeout = args.timeout
    monitor.min_packets_for_analysis = args.min_packets
    
    monitor.start_monitoring()

if __name__ == "__main__":
    main()

