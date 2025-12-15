from flask import Flask, render_template, jsonify
import pandas as pd
import plotly
import plotly.graph_objs as go
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__, template_folder='/media/sf_SharedVM/templates')

CSV_PATH = "/media/sf_SharedVM/Attack_LDDOS.csv"

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({'error': 'No data available'})
        
        df = pd.read_csv(CSV_PATH)
        
        # FILTER OUT ZERO-PACKET FLOWS
        df = df[df['packet_count'] > 0]
        
        total_flows = len(df)
        unique_sources = df['ipv4_src'].nunique()
        total_packets = df['packet_count'].sum()
        total_bytes = df['byte_count'].sum()
        
        # Attack detection: Low packets AND short duration
        attacks = df[(df['packet_count'] > 0) & (df['packet_count'] <= 2) & (df['duration_sec'] <= 5)]
        attack_count = len(attacks)
        
        return jsonify({
            'total_flows': int(total_flows),
            'unique_sources': int(unique_sources),
            'total_packets': int(total_packets),
            'total_bytes': int(total_bytes),
            'attack_count': int(attack_count),
            'legitimate_count': int(total_flows - attack_count)
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/traffic_timeline')
def traffic_timeline():
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({'error': 'No data available'})
            
        df = pd.read_csv(CSV_PATH)
        
        # FILTER OUT ZERO-PACKET FLOWS
        df = df[df['packet_count'] > 0]
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        df_grouped = df.groupby(pd.Grouper(key='timestamp', freq='1S')).agg({
            'packet_count': 'sum',
            'ipv4_src': 'count'
        }).reset_index()
        
        trace1 = go.Scatter(
            x=df_grouped['timestamp'],
            y=df_grouped['packet_count'],
            mode='lines',
            name='Packets/sec',
            line=dict(color='blue')
        )
        
        trace2 = go.Scatter(
            x=df_grouped['timestamp'],
            y=df_grouped['ipv4_src'],
            mode='lines',
            name='Flows/sec',
            line=dict(color='green'),
            yaxis='y2'
        )
        
        layout = go.Layout(
            title='Traffic Timeline',
            xaxis=dict(title='Time'),
            yaxis=dict(title='Packets', side='left'),
            yaxis2=dict(title='Flows', overlaying='y', side='right'),
            hovermode='closest'
        )
        
        fig = go.Figure(data=[trace1, trace2], layout=layout)
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/top_sources')
def top_sources():
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({'error': 'No data available'})
            
        df = pd.read_csv(CSV_PATH)
        
        # FILTER OUT ZERO-PACKET FLOWS
        df = df[df['packet_count'] > 0]
        
        top_ips = df.groupby('ipv4_src').agg({
            'packet_count': 'sum',
            'ipv4_src': 'count'
        }).rename(columns={'ipv4_src': 'flow_count'}).sort_values('packet_count', ascending=False).head(10)
        
        trace = go.Bar(
            x=top_ips.index,
            y=top_ips['packet_count'],
            marker=dict(color='red'),
            name='Packets'
        )
        
        layout = go.Layout(
            title='Top 10 Source IPs by Packet Count',
            xaxis=dict(title='Source IP'),
            yaxis=dict(title='Total Packets')
        )
        
        fig = go.Figure(data=[trace], layout=layout)
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/attack_distribution')
def attack_distribution():
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({'error': 'No data available'})
            
        df = pd.read_csv(CSV_PATH)
        
        # FILTER OUT ZERO-PACKET FLOWS
        df = df[df['packet_count'] > 0]
        
        df['type'] = 'Legitimate'
        # Attack: Has packets (>0) BUT low count (<=2) AND short duration (<=5s)
        df.loc[(df['packet_count'] > 0) & (df['packet_count'] <= 2) & (df['duration_sec'] <= 5), 'type'] = 'Attack'
        
        type_counts = df['type'].value_counts()
        
        trace = go.Pie(
            labels=type_counts.index,
            values=type_counts.values,
            marker=dict(colors=['green', 'red'])
        )
        
        layout = go.Layout(title='Traffic Distribution')
        
        fig = go.Figure(data=[trace], layout=layout)
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/packet_size_distribution')
def packet_size_distribution():
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({'error': 'No data available'})
            
        df = pd.read_csv(CSV_PATH)
        
        # FILTER OUT ZERO-PACKET FLOWS
        df = df[df['packet_count'] > 0]
        
        df['bytes_per_packet'] = df['byte_count'] / df['packet_count']
        
        trace = go.Histogram(
            x=df['bytes_per_packet'],
            nbinsx=50,
            marker=dict(color='blue'),
            name='Bytes per Packet'
        )
        
        layout = go.Layout(
            title='Packet Size Distribution',
            xaxis=dict(title='Bytes per Packet'),
            yaxis=dict(title='Frequency')
        )
        
        fig = go.Figure(data=[trace], layout=layout)
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("Starting LDDOS Dashboard on http://0.0.0.0:5000")
    print("Press CTRL+C to stop")
    app.run(host='0.0.0.0', port=5000, debug=True)