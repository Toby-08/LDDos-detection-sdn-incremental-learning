# Detecting LDDoS Attacks in SDN using Incremental Learning

This repository implements a real-time framework for detecting and mitigating Low-rate Distributed Denial-of-Service (LDDoS) attacks in Software Defined Networking (SDN) environments. The system integrates OpenFlow-based traffic monitoring with incremental (online) machine learning models to adapt to evolving attack patterns.

## Problem Statement

Low-rate DDoS (LDDoS) attacks generate traffic patterns that closely resemble legitimate flows while gradually degrading network performance. Traditional SDN security mechanisms and offline-trained ML models struggle to detect such attacks due to:
- Low attack intensity
- Dynamic traffic behavior
- Lack of adaptability to concept drift

This project addresses these limitations by using incremental learning models trained on real-time OpenFlow statistics.

## System Overview

The framework follows a closed-loop SDN security workflow:

1. Traffic generation (normal + LDDoS) in an emulated SDN topology.
2. Collection of flow-level statistics via Ryu (OpenFlow 1.3).
3. Feature extraction from flow statistics.
4. Online classification using incremental ML algorithms.
5. Immediate mitigation by installing flow rules on detection.

## Features

- Incremental machine learning for adaptive LDDoS detection
- Real-time flow-level monitoring using Ryu controller
- Support for multiple LDDoS attack patterns
- Automatic mitigation via OpenFlow rules
- Evaluation on both synthetic and benchmark datasets

## Incremental Learning Models

The following online learning algorithms are used:
- Passive-Aggressive (PA)
- Online Support Vector Machine (Online SVM)

These models update incrementally as new flow statistics arrive, allowing adaptation to changing traffic distributions.

## Traffic Features

Features are extracted from OpenFlow flow statistics, including:
- Flow duration
- Packet count
- Byte count
- Packet rate
- Byte rate
- Entropy-based measures (source/destination)

## Experimental Setup

### SDN Environment
- Mininet / Mininet-WiFi for topology emulation
- Ryu controller (OpenFlow 1.3)

### Attack Simulation
- Hping3
- D-ITG
- Scapy

### Datasets
- CICDDoS2019
- InSDN
- Slow-Read DDoS

Custom datasets are generated to simulate multiple LDDoS scenarios.

## How to Run (High-Level)

1. Start Ryu controller with the detection application
2. Launch Mininet topology
3. Generate normal and LDDoS traffic
4. Observe detection and mitigation logs
   

## Limitations

- Performance depends on flow statistics polling interval
- Evaluation limited to emulated SDN environments
- Accuracy may vary across LDDoS variants

## Future Work

- Integration with deep online learning models
- Controller performance optimization
- Multi-controller SDN environments
- Deployment on hardware switches 



MIT License

