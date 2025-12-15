from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib import hub
from ryu.controller import dpset
import pandas as pd
from datetime import datetime, timedelta
import pickle
import os
import random
from collections import defaultdict
from river import tree
import traceback


class IPSwitchStats(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"dpset": dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(IPSwitchStats, self).__init__(*args, **kwargs)
        self.dpset = kwargs["dpset"]
        self.flow_data = []
        self.csv_path = "/media/sf_VM/Ubuntu24.04.3/Attack_LDDOS.csv"
        self.model_path = "/media/sf_VM/Ubuntu24.04.3/SGTClassifier_v2_model.pkl"
        self.last_processed_index = 0

        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)
            self.logger.info("Deleted old CSV: %s", self.csv_path)
        
        if os.path.exists(self.model_path):
            self.logger.info("Found existing model: %s", self.model_path)
        
        self.legitimate_ips = {"10.0.0.1", "10.0.0.2"}
        
        self.ip_flow_stats = defaultdict(lambda: {
            'count': 0,
            'total_packets': 0,
            'total_bytes': 0,
            'first_seen': None,
            'last_seen': None,
            'suspicion_score': 0,
            'drop_rate': 0.0,
            'packets_dropped': 0,
            'previous_rate': 0,
            'drop_started': None,        
            'drop_duration': 0,          
            'consecutive_attacks': 0,   
            'cleared_count': 0,
            'syn_flows': 0  
        })
        
        # Statistics
        self.total_attacks_detected = 0
        self.total_legitimate_allowed = 0
        self.total_packets_dropped = 0
        self.total_flows_installed = 0  
        self.total_packets_received = 0  
        
        # Separate counters for allowed vs total
        self.ip_packet_counter = defaultdict(int)
        self.ip_total_received = defaultdict(int)
        
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.logger.info("✓ Model loaded successfully")
        except Exception as e:
            self.logger.warning("○ No existing model: %s", str(e))
            self.logger.info("⚙ Creating & pre-training NEW model...")
            
            self.model = tree.HoeffdingTreeClassifier(
                grace_period=200,
                delta=0.0001,
            )
            
            # PRE-TRAIN with synthetic data
            self._pretrain_model()
            
            self.logger.info("✓ New model created & pre-trained")
    
        hub.spawn(self.stats_loop)
        hub.spawn(self.model_inference_loop)
        hub.spawn(self.adaptation_monitor_loop)
        
        self.logger.error("=" * 70)
        self.logger.error("LDDOS DETECTION SYSTEM STARTED")
        self.logger.error("Detection: ML-Driven (with SYN flood detection)")
        self.logger.error("Model: %s", "Loaded" if os.path.exists(self.model_path) else "New")
        self.logger.error("=" * 70)

    def _pretrain_model(self):
        """Pre-train model with synthetic samples including SYN floods"""
        self.logger.info("Pre-training model with synthetic data...")
        
        # Generate 40 synthetic legitimate samples
        for i in range(40):
            x_legit = {
                'dpid': 1.0 + random.uniform(0, 0.1),
                'packet_count': random.uniform(10, 100),
                'byte_count': random.uniform(500, 5000),
                'duration_sec': random.uniform(5, 30),
                'suspicion_score': random.uniform(0, 2),
                'unique_sources': random.uniform(1, 5),
                'bytes_per_packet': random.uniform(50, 500),
                'is_zero_byte': 0.0  
            }
            try:
                self.model.learn_one(x_legit, 0)
            except:
                pass
        
        # Generate 30 synthetic LDoS attacks
        for i in range(30):
            x_ldos = {
                'dpid': 1.0 + random.uniform(0, 0.1),
                'packet_count': random.uniform(1, 5),
                'byte_count': random.uniform(50, 500),
                'duration_sec': random.uniform(0.1, 2),
                'suspicion_score': random.uniform(7, 10),
                'unique_sources': random.uniform(20, 100),
                'bytes_per_packet': random.uniform(40, 150),
                'is_zero_byte': 0.0
            }
            try:
                self.model.learn_one(x_ldos, 1)
            except:
                pass
        
        # Generate 30 synthetic SYN flood attacks
        for i in range(30):
            x_syn = {
                'dpid': 1.0 + random.uniform(0, 0.1),
                'packet_count': random.uniform(1, 3),  # Few packets
                'byte_count': random.uniform(40, 80),  # Only headers
                'duration_sec': random.uniform(0.1, 1),  # Very short
                'suspicion_score': random.uniform(8, 10),  # High suspicion
                'unique_sources': random.uniform(30, 150),  # Highly distributed
                'bytes_per_packet': random.uniform(40, 60),  # SYN packet size
                'is_zero_byte': 1.0  # ✅ Flag for SYN
            }
            try:
                self.model.learn_one(x_syn, 1)
            except:
                pass
    
        self.logger.info("✓ Pre-trained with 100 synthetic samples (50 legit, 50 attack)")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.logger.info("Switch connected: DPID=%s", dp.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0,
                                      match=match, instructions=inst))
        self.logger.info("Default flow rule installed")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        in_port = msg.match["in_port"]

        # Handle non-IP packets
        if ip_pkt is None:
            self.logger.debug("Non-IP packet on port %d, flooding", in_port)
            out = parser.OFPPacketOut(dp, msg.buffer_id, in_port,
                                      [parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                                      msg.data)
            dp.send_msg(out)
            return

        src = ip_pkt.src
        dst = ip_pkt.dst
        
        # Count ALL packets received (before any drop decision)
        self.ip_total_received[src] += 1
        self.total_packets_received += 1
        
        self.logger.debug("Packet #%d from %s → %s (total from IP: %d)", 
                         self.total_packets_received, src, dst, self.ip_total_received[src])

        ip_stats = self.ip_flow_stats[src]
        drop_rate = ip_stats['drop_rate']
        
        # Check if drop period expired
        if drop_rate > 0 and ip_stats['drop_started']:
            elapsed = (datetime.now() - ip_stats['drop_started']).total_seconds()
            
            if elapsed > ip_stats['drop_duration']:
                self.logger.warning("DROP EXPIRED: %s (%.0fs)", src, elapsed)
                self.logger.warning("   Previous: Score=%d/10, Drop=%.0f%%, Dropped=%d", 
                                  ip_stats['suspicion_score'], drop_rate * 100, 
                                  ip_stats['packets_dropped'])
                
                ip_stats['drop_rate'] = 0.0
                ip_stats['suspicion_score'] = 2
                ip_stats['drop_started'] = None
                ip_stats['packets_dropped'] = 0
                ip_stats['cleared_count'] += 1
                ip_stats['count'] = 0
                ip_stats['total_packets'] = 0
                ip_stats['total_bytes'] = 0
                ip_stats['syn_flows'] = 0  
                ip_stats['first_seen'] = datetime.now()
                
                drop_rate = 0.0
                self.logger.warning("   Reset to monitoring (score=2/10)")
        
        # Probabilistic drop
        if drop_rate > 0:
            random_value = random.random()
            should_drop = random_value < drop_rate
            
            self.logger.debug("   Drop: %.3f vs %.3f → %s", 
                            random_value, drop_rate, "DROP" if should_drop else "ALLOW")
            
            if should_drop:
                ip_stats['packets_dropped'] += 1
                self.total_packets_dropped += 1
                
                if ip_stats['drop_started']:
                    elapsed = (datetime.now() - ip_stats['drop_started']).total_seconds()
                    remaining = max(0, ip_stats['drop_duration'] - elapsed)
                    
                    self.logger.warning("DROPPED: %s → %s", src, dst)
                    self.logger.warning("   Drop=%.0f%%, Score=%d/10, Remaining=%.0fs", 
                                      drop_rate * 100, ip_stats['suspicion_score'], remaining)
                    self.logger.warning("   Total=%d | Dropped=%d | Allowed=%d | Effectiveness=%.1f%%",
                                      self.ip_total_received[src],
                                      ip_stats['packets_dropped'],
                                      self.ip_packet_counter[src],
                                      (ip_stats['packets_dropped'] / self.ip_total_received[src] * 100) if self.ip_total_received[src] > 0 else 0)
            
                return  # Drop without flow rule
        
        # Packet allowed
        self.ip_packet_counter[src] += 1
        
        self.logger.info("ALLOWED: %s → %s", src, dst)
        self.logger.info("   Reason: %s", 
                    "Whitelisted" if src in self.legitimate_ips 
                    else f"Drop={drop_rate * 100:.0f}% (passed)")
        self.logger.info("   Stats: %d allowed / %d total from %s", 
                       self.ip_packet_counter[src], self.ip_total_received[src], src)
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst)
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=10,
            match=match,
            instructions=inst,
            idle_timeout=10,
            hard_timeout=30
        ))

        dp.send_msg(parser.OFPPacketOut(dp, msg.buffer_id, in_port, actions, msg.data))
        
        self.total_flows_installed += 1
        
        self.logger.info("   Flow installed (priority=10, idle=10s, hard=30s)")
        self.logger.info("   Total flows: %d", self.total_flows_installed)

    def stats_loop(self):
        """Collect flow stats every 2 seconds"""
        self.logger.info("Stats collector started (interval: 2s)")
        
        while True:
            for dpid, dp in self.dpset.get_all():
                req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(2)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        
        flows_added = 0
        flows_skipped_priority = 0
        flows_zero_byte = 0  

        for stat in ev.msg.body:
            # Skip default flow (priority 0)
            if stat.priority == 0:
                flows_skipped_priority += 1
                continue
            
            ipv4_src = stat.match.get('ipv4_src', None)
            ipv4_dst = stat.match.get('ipv4_dst', None)

            if ipv4_src is None or ipv4_dst is None:
                continue

         
            is_zero_byte = (stat.packet_count == 0)
            
            if is_zero_byte:
                flows_zero_byte += 1
                self.total_syn_flows += 1
                self.ip_flow_stats[ipv4_src]['syn_flows'] += 1
                self.logger.debug("SYN flow detected: %s → %s", ipv4_src, ipv4_dst)

            entry = {
                "timestamp": datetime.now(),
                "dpid": dpid,
                "ipv4_src": ipv4_src,
                "ipv4_dst": ipv4_dst,
                "priority": stat.priority,
                "packet_count": max(1, stat.packet_count),  
                "byte_count": max(40, stat.byte_count),  
                "duration_sec": max(0.1, stat.duration_sec),  
                "is_zero_byte": 1 if is_zero_byte else 0  
            }

            self.flow_data.append(entry)
            flows_added += 1
            
            if is_zero_byte:
                self.logger.debug("SYN: %s → %s | Dur=%ds (zero-byte flow)",
                                ipv4_src, ipv4_dst, stat.duration_sec)
            else:
                self.logger.debug("Flow: %s → %s | Pkts=%d | Bytes=%d | Dur=%ds",
                                ipv4_src, ipv4_dst, stat.packet_count, 
                                stat.byte_count, stat.duration_sec)

        if flows_added > 0:
            self.logger.debug("Stats: +%d flows (%d SYN), skipped %d, total=%d",
                            flows_added, flows_zero_byte, flows_skipped_priority, len(self.flow_data))

        if self.flow_data:
            pd.DataFrame(self.flow_data).to_csv(self.csv_path, index=False)

    def calculate_suspicion_score(self, row, src_ip_counts, unique_sources, is_known_legitimate):
        score = 0
        src_ip = row['ipv4_src']
        stats = self.ip_flow_stats[src_ip]
        reasons = []
        
        # ✅ NEW: Detect SYN flood pattern
        is_syn_flow = (row.get('is_zero_byte', 0) == 1)
        
        if is_syn_flow:
            score += 4
            reasons.append("SYN flood pattern (zero-byte) +4")
        
        # Low packet count
        if row['packet_count'] <= 2:
            score += 3
            reasons.append(f"Very low pkts ({row['packet_count']} ≤ 2) +3")
        elif row['packet_count'] <= 5:
            score += 1
            reasons.append(f"Low pkts ({row['packet_count']} ≤ 5) +1")
        
        # Short duration
        if row['duration_sec'] <= 2:
            score += 3
            reasons.append(f"Very short ({row['duration_sec']}s ≤ 2s) +3")
        elif row['duration_sec'] <= 5:
            score += 2
            reasons.append(f"Short ({row['duration_sec']}s ≤ 5s) +2")
        elif row['duration_sec'] <= 10:
            score += 1
            reasons.append(f"Medium ({row['duration_sec']}s ≤ 10s) +1")
        
        # Distributed pattern
        if unique_sources > 50:
            score += 3
            reasons.append(f"High distribution ({unique_sources} > 50) +3")
        elif unique_sources > 20:
            score += 2
            reasons.append(f"Medium distribution ({unique_sources} > 20) +2")
        elif unique_sources > 10:
            score += 1
            reasons.append(f"Some distribution ({unique_sources} > 10) +1")
        
        # ✅ NEW: Multiple SYN flows from same IP
        if stats['syn_flows'] > 5:
            score += 3
            reasons.append(f"Repeated SYN ({stats['syn_flows']} flows) +3")
        elif stats['syn_flows'] > 2:
            score += 1
            reasons.append(f"Some SYN ({stats['syn_flows']} flows) +1")
        
        # Single-packet sources
        if src_ip_counts[src_ip] == 1 and row['packet_count'] <= 2:
            score += 2
            reasons.append("Single flow with ≤2 pkts +2")
        
        # Low average
        if stats['count'] > 0:
            avg_packets = stats['total_packets'] / stats['count']
            if avg_packets < 3:
                score += 2
                reasons.append(f"Low avg ({avg_packets:.1f} < 3) +2")
            elif avg_packets < 10:
                score += 1
                reasons.append(f"Medium avg ({avg_packets:.1f} < 10) +1")
        
        # Small packets (typical SYN header = 40-60 bytes)
        if row['packet_count'] > 0:
            bytes_per_packet = row['byte_count'] / row['packet_count']
            if bytes_per_packet < 70:
                score += 3
                reasons.append(f"SYN-size packet ({bytes_per_packet:.0f}B < 70B) +3")
            elif bytes_per_packet < 100:
                score += 2
                reasons.append(f"Small size ({bytes_per_packet:.0f}B < 100B) +2")
            elif bytes_per_packet < 300:
                score += 1
                reasons.append(f"Medium size ({bytes_per_packet:.0f}B < 300B) +1")
        
        # Whitelist
        if is_known_legitimate:
            original_score = score
            score = max(0, score - 8)
            reasons.append(f"Whitelisted: {original_score} - 8 = {score}")
        
        return min(score, 10), reasons

    def update_drop_rate(self, src_ip, suspicion_score):
        stats = self.ip_flow_stats[src_ip]
        
        if suspicion_score >= 9:
            drop_rate = 1.0
            drop_duration = 600
            severity = "SEVERE"
        elif suspicion_score >= 7:
            drop_rate = 0.8
            drop_duration = 300
            severity = "HIGH"
        elif suspicion_score >= 5:
            drop_rate = 0.5
            drop_duration = 120
            severity = "MEDIUM"
        elif suspicion_score >= 3:
            drop_rate = 0.3
            drop_duration = 60
            severity = "LOW"
        else:
            drop_rate = 0.0
            drop_duration = 0
            severity = "NONE"
        
        # Repeat offender penalty
        if stats['cleared_count'] > 0 and drop_rate > 0:
            multiplier = 1 + (stats['cleared_count'] * 0.5)
            drop_duration = int(drop_duration * multiplier)
            drop_rate = min(1.0, drop_rate * 1.2)
            
            self.logger.error("REPEAT OFFENDER: %s (cleared %dx)", src_ip, stats['cleared_count'])
            self.logger.error("  Penalty: %.1f duration, %.0f%% drop", multiplier, drop_rate * 100)
        
        if drop_rate > 0 and stats['drop_started'] is None:
            stats['drop_started'] = datetime.now()
            stats['drop_duration'] = drop_duration
            stats['consecutive_attacks'] += 1
            
            # ✅ NEW: Show attack type
            attack_type = "SYN FLOOD" if stats['syn_flows'] > 3 else "LDDOS"
            
            self.logger.error("=" * 70)
            self.logger.error("MITIGATION ACTIVATED: %s (%s)", src_ip, attack_type)
            self.logger.error("=" * 70)
            self.logger.error("Severity: %s (%d/10)", severity, suspicion_score)
            self.logger.error("Drop: %.0f%% (Allow: %.0f%%)", drop_rate * 100, (1 - drop_rate) * 100)
            self.logger.error("Duration: %ds (%.1fm)", drop_duration, drop_duration / 60.0)
            if stats['syn_flows'] > 0:
                self.logger.error("SYN flows: %d", stats['syn_flows'])
            self.logger.error("Attack #%d from this IP", stats['consecutive_attacks'])
            self.logger.error("=" * 70)
        
        stats['drop_rate'] = drop_rate
        stats['suspicion_score'] = suspicion_score
        
        return drop_rate

    def adaptation_monitor_loop(self):
        self.logger.info("Adaptation monitor started (interval: 30s)")
        
        while True:
            hub.sleep(30)
            
            for src_ip, stats in list(self.ip_flow_stats.items()):
                if stats['drop_rate'] == 0:
                    continue
                
                if stats['last_seen'] and stats['first_seen']:
                    time_window = (stats['last_seen'] - stats['first_seen']).total_seconds()
                    if time_window > 0:
                        current_rate = stats['total_packets'] / time_window
                        
                        if stats['previous_rate'] > 0:
                            rate_reduction = (stats['previous_rate'] - current_rate) / stats['previous_rate']
                            
                            if rate_reduction > 0.3:
                                old_score = stats['suspicion_score']
                                old_drop = stats['drop_rate']
                                stats['suspicion_score'] = max(0, stats['suspicion_score'] - 2)
                                stats['drop_rate'] = max(0, stats['drop_rate'] - 0.2)
                                
                                self.logger.info("ADAPTATION: %s (rate ↓%.0f%%)", src_ip, rate_reduction * 100)
                                self.logger.info("  %d→%d score | %.0f%%→%.0f%% drop",
                                               old_score, stats['suspicion_score'],
                                               old_drop * 100, stats['drop_rate'] * 100)
                            else:
                                old_score = stats['suspicion_score']
                                old_drop = stats['drop_rate']
                                stats['suspicion_score'] = min(10, stats['suspicion_score'] + 1)
                                stats['drop_rate'] = min(1.0, stats['drop_rate'] + 0.1)
                                
                                self.logger.warning("ESCALATION: %s (persists)", src_ip)
                                self.logger.warning("  %d→%d score | %.0f%%→%.0f%% drop",
                                                  old_score, stats['suspicion_score'],
                                                  old_drop * 100, stats['drop_rate'] * 100)
                        
                        stats['previous_rate'] = current_rate

    def model_inference_loop(self):
        self.logger.info("ML inference started (interval: 5s)")
        
        while True:
            hub.sleep(5)
            
            if self.model is None:
                continue
            
            if not os.path.exists(self.csv_path):
                continue
            
            try:
                df = pd.read_csv(self.csv_path)
                
                # ✅ CHANGED: Don't filter zero-packet flows!
                # df = df[df['packet_count'] > 0]  # ❌ REMOVED THIS LINE
                
                if len(df) == 0:
                    continue
                
                new_flows = df.iloc[self.last_processed_index:]
                
                if len(new_flows) == 0:
                    continue
                
                self.logger.info("=" * 70)
                self.logger.info("ML ANALYSIS: %d new flows", len(new_flows))
                
                src_ip_counts = new_flows['ipv4_src'].value_counts()
                unique_sources = len(src_ip_counts)
                syn_count = new_flows['is_zero_byte'].sum() if 'is_zero_byte' in new_flows.columns else 0
                
                self.logger.info("Unique sources: %d | SYN flows: %d", unique_sources, int(syn_count))
                
                attacks_in_batch = 0
                legitimate_in_batch = 0
                skipped = 0
                ml_train_success = 0
                ml_train_failed = 0
                
                for idx, row in new_flows.iterrows():
                    src_ip = row['ipv4_src']
                    
                    stats = self.ip_flow_stats[src_ip]
                    stats['count'] += 1
                    stats['total_packets'] += row['packet_count']
                    stats['total_bytes'] += row['byte_count']
                    stats['last_seen'] = datetime.now()
                    if stats['first_seen'] is None:
                        stats['first_seen'] = datetime.now()
                    
                    is_known_legitimate = src_ip in self.legitimate_ips
                    
                    suspicion_score, reasons = self.calculate_suspicion_score(
                        row, src_ip_counts, unique_sources, is_known_legitimate
                    )
                    
                    if suspicion_score < 0:
                        skipped += 1
                        continue
                    
                    # Enhanced ML features with jitter and SYN detection
                    x = {
                        'dpid': float(row['dpid']) + random.uniform(0.001, 0.002),
                        'packet_count': float(row['packet_count']) + random.uniform(0.001, 0.002),
                        'byte_count': float(row['byte_count']) + random.uniform(0.001, 0.002),
                        'duration_sec': max(0.1, float(row['duration_sec'])) + random.uniform(0.001, 0.002),
                        'suspicion_score': float(suspicion_score) + random.uniform(0.001, 0.002),
                        'unique_sources': float(unique_sources) + random.uniform(0.001, 0.002),
                        'bytes_per_packet': (float(row['byte_count']) / max(1, float(row['packet_count']))) + random.uniform(0.001, 0.002),
                        'is_zero_byte': float(row.get('is_zero_byte', 0)) + random.uniform(0, 0.001) 
                    }
                    
                    # ML makes decision
                    try:
                        ml_prediction = self.model.predict_one(x)
                        
                        if is_known_legitimate:
                            is_attack = False
                        else:
                            is_attack = (ml_prediction == 1)
                        
                    except Exception as e:
                        self.logger.debug("ML prediction failed: %s", str(e))
                        is_attack = (suspicion_score >= 3 and not is_known_legitimate)
                    
                    if is_attack:
                        drop_rate = self.update_drop_rate(src_ip, suspicion_score)
                        
                        flow_type = "SYN" if row.get('is_zero_byte', 0) == 1 else "DATA"
                        self.logger.error("ATTACK (%s): %s→%s | Pkts=%d | Dur=%.1fs | Score=%d/10 | Drop=%.0f%%",
                                        flow_type, src_ip, row['ipv4_dst'], row['packet_count'], 
                                        row['duration_sec'], suspicion_score, drop_rate * 100)
                        for reason in reasons[:3]:
                            self.logger.error("     %s", reason)
                        
                        attacks_in_batch += 1
                        self.total_attacks_detected += 1
                    else:
                        self.logger.info("LEGIT: %s→%s | Pkts=%d | Dur=%.1fs | Score=%d/10",
                                       src_ip, row['ipv4_dst'], row['packet_count'], 
                                       row['duration_sec'], suspicion_score)
                        
                        legitimate_in_batch += 1
                        self.total_legitimate_allowed += 1
                    
                    # Train model
                    y_true = 1 if is_attack else 0
                    try:
                        self.model.learn_one(x, y_true)
                        ml_train_success += 1
                        self.logger.debug("   ML trained: label=%d", y_true)
                    except ZeroDivisionError:
                        ml_train_failed += 1
                        self.logger.debug("  ML training skipped (division by zero)")
                    except Exception as e:
                        ml_train_failed += 1
                        self.logger.debug("   ML training failed: %s", str(e))
        
                self.last_processed_index = len(df)
                
                # Save model
                try:
                    with open(self.model_path, 'wb') as f:
                        pickle.dump(self.model, f)
                    self.logger.debug(" Model saved")
                except Exception as e:
                    self.logger.error(" Model save failed: %s", str(e))
                
                self.logger.info("-" * 70)
                self.logger.info(" BATCH: %d attacks | %d legit | %d skipped",
                            attacks_in_batch, legitimate_in_batch, skipped)
                self.logger.info("   ML Training: %d success / %d failed",
                            ml_train_success, ml_train_failed)
                self.logger.info("   SYN floods detected: %d (total: %d)",
                            int(syn_count), self.total_syn_flows)
                self.logger.info("   Dropped: %d/%d packets (%.1f%%)",
                            self.total_packets_dropped, self.total_packets_received,
                            (self.total_packets_dropped / self.total_packets_received * 100) if self.total_packets_received > 0 else 0)
                self.logger.info("TOTAL: %d attacks detected | %d legitimate allowed",
                            self.total_attacks_detected, self.total_legitimate_allowed)
                self.logger.info("=" * 70)
            
            except Exception as e:
                self.logger.error(" Error in ML loop: %s", str(e))
                self.logger.error(traceback.format_exc())
