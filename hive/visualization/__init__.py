from typing import Dict, List, Any, Optional
import networkx as nx
from datetime import datetime, timedelta
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

class ProcessGraph:
    """Générateur de graphes de processus"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
    
    def add_process(self, pid: int, name: str, parent_pid: Optional[int] = None) -> None:
        """Ajoute un processus au graphe"""
        self.graph.add_node(pid, name=name)
        if parent_pid:
            self.graph.add_edge(parent_pid, pid)
    
    def generate_plot(self) -> Dict[str, Any]:
        """Génère une visualisation du graphe"""
        pos = nx.spring_layout(self.graph)
        
        # Création des traces pour les nœuds
        node_trace = go.Scatter(
            x=[],
            y=[],
            text=[],
            mode='markers+text',
            hoverinfo='text',
            marker=dict(
                size=20,
                color='lightblue',
                line=dict(width=2)
            )
        )
        
        # Ajout des positions des nœuds
        for node in self.graph.nodes():
            x, y = pos[node]
            node_trace['x'] += tuple([x])
            node_trace['y'] += tuple([y])
            node_trace['text'] += tuple([f"{node}: {self.graph.nodes[node]['name']}"])
        
        # Création des traces pour les arêtes
        edge_trace = go.Scatter(
            x=[],
            y=[],
            line=dict(width=1, color='#888'),
            hoverinfo='none',
            mode='lines'
        )
        
        # Ajout des positions des arêtes
        for edge in self.graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += tuple([x0, x1, None])
            edge_trace['y'] += tuple([y0, y1, None])
        
        # Création de la figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                       ))
        
        return fig.to_dict()

class NetworkMap:
    """Générateur de cartes réseau"""
    
    def __init__(self):
        self.connections = []
    
    def add_connection(self, source: str, target: str, protocol: str, port: int) -> None:
        """Ajoute une connexion réseau"""
        self.connections.append({
            'source': source,
            'target': target,
            'protocol': protocol,
            'port': port
        })
    
    def generate_plot(self) -> Dict[str, Any]:
        """Génère une visualisation de la carte réseau"""
        # Création d'un graphe
        G = nx.Graph()
        
        # Ajout des connexions
        for conn in self.connections:
            G.add_edge(conn['source'], conn['target'],
                      protocol=conn['protocol'],
                      port=conn['port'])
        
        # Calcul des positions
        pos = nx.spring_layout(G)
        
        # Création des traces pour les nœuds
        node_trace = go.Scatter(
            x=[],
            y=[],
            text=[],
            mode='markers+text',
            hoverinfo='text',
            marker=dict(
                size=20,
                color='lightgreen',
                line=dict(width=2)
            )
        )
        
        # Ajout des positions des nœuds
        for node in G.nodes():
            x, y = pos[node]
            node_trace['x'] += tuple([x])
            node_trace['y'] += tuple([y])
            node_trace['text'] += tuple([node])
        
        # Création des traces pour les arêtes
        edge_trace = go.Scatter(
            x=[],
            y=[],
            line=dict(width=1, color='#888'),
            hoverinfo='text',
            text=[],
            mode='lines'
        )
        
        # Ajout des positions des arêtes
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += tuple([x0, x1, None])
            edge_trace['y'] += tuple([y0, y1, None])
            edge_trace['text'] += tuple([
                f"{G.edges[edge]['protocol']}:{G.edges[edge]['port']}"
            ])
        
        # Création de la figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                       ))
        
        return fig.to_dict()

class TimelineVisualizer:
    """Générateur de visualisations temporelles"""
    
    def __init__(self):
        self.events = []
    
    def add_event(self, timestamp: datetime, event_type: str, description: str) -> None:
        """Ajoute un événement à la timeline"""
        self.events.append({
            'timestamp': timestamp,
            'type': event_type,
            'description': description
        })
    
    def generate_plot(self) -> Dict[str, Any]:
        """Génère une visualisation de la timeline"""
        # Conversion en DataFrame
        df = pd.DataFrame(self.events)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Création de la figure
        fig = px.scatter(df, x='timestamp', y='type',
                        hover_data=['description'],
                        title='Timeline des événements')
        
        # Personnalisation du layout
        fig.update_layout(
            xaxis_title='Date et heure',
            yaxis_title='Type d\'événement',
            hovermode='closest'
        )
        
        return fig.to_dict()

class DashboardGenerator:
    """Générateur de tableaux de bord"""
    
    def __init__(self):
        self.metrics = {}
    
    def add_metric(self, name: str, value: float, timestamp: datetime) -> None:
        """Ajoute une métrique"""
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append({
            'timestamp': timestamp,
            'value': value
        })
    
    def generate_plot(self) -> Dict[str, Any]:
        """Génère une visualisation du tableau de bord"""
        # Création des sous-graphiques
        fig = go.Figure()
        
        for metric_name, data in self.metrics.items():
            df = pd.DataFrame(data)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig.add_trace(go.Scatter(
                x=df['timestamp'],
                y=df['value'],
                name=metric_name,
                mode='lines+markers'
            ))
        
        # Personnalisation du layout
        fig.update_layout(
            title='Tableau de bord des métriques',
            xaxis_title='Date et heure',
            yaxis_title='Valeur',
            hovermode='x unified'
        )
        
        return fig.to_dict() 