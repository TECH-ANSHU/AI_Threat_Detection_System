import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from sklearn.metrics import confusion_matrix
from utils.preprocessing import ALL_FEATURES, NUMERIC_FEATURES

# Custom colors for a sleek dark cyber theme
SEVERITY_COLORS = {
    'CRITICAL': '#FF3B30',  # Soft Neon Red
    'HIGH': '#FF9500',      # Soft Neon Orange
    'MEDIUM': '#FFCC00',    # Soft Neon Yellow
    'LOW': '#34C759'        # Soft Neon Green
}

ATTACK_COLORS = {
    'Benign': '#2FA4FF',
    'DDoS': '#FF3D68',
    'Port Scan': '#FF8000',
    'Brute Force': '#FFD000',
    'Infiltration': '#A100FF'
}

def plot_severity_donut(severity_counts_dict):
    """Generates a premium Plotly donut chart showing threat severity distribution."""
    if not severity_counts_dict:
        # Return an empty/placeholder figure
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#E0E0E0',
            title="No alerts logged yet"
        )
        return fig
        
    df = pd.DataFrame(list(severity_counts_dict.items()), columns=['Severity', 'Count'])
    
    # Filter out Low if it represents benign and we only want to show malicious threats,
    # or display whatever comes in.
    df['Severity'] = df['Severity'].str.upper()
    
    colors = [SEVERITY_COLORS.get(sev, '#8E8E93') for sev in df['Severity']]
    
    fig = go.Figure(data=[go.Pie(
        labels=df['Severity'],
        values=df['Count'],
        hole=.5,
        marker=dict(colors=colors, line=dict(color='#0e1117', width=2)),
        textinfo='percent+label',
        hoverinfo='label+value'
    )])
    
    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        margin=dict(t=30, b=30, l=10, r=10),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#E2E8F0',
        height=300
    )
    return fig

def plot_attack_bar(attack_counts_dict):
    """Generates an interactive bar chart of attack distribution."""
    if not attack_counts_dict:
        fig = go.Figure()
        return fig
        
    df = pd.DataFrame(list(attack_counts_dict.items()), columns=['Attack Type', 'Count'])
    df = df.sort_values(by='Count', ascending=True)
    
    colors = [ATTACK_COLORS.get(atk, '#00F0FF') for atk in df['Attack Type']]
    
    fig = go.Figure(data=[go.Bar(
        x=df['Count'],
        y=df['Attack Type'],
        orientation='h',
        marker=dict(color=colors, line=dict(color='#0e1117', width=1)),
        text=df['Count'],
        textposition='auto',
        hoverinfo='x+y'
    )])
    
    fig.update_layout(
        xaxis_title="Incident Count",
        yaxis_title="Threat Category",
        margin=dict(t=30, b=30, l=10, r=10),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#E2E8F0',
        xaxis=dict(showgrid=True, gridcolor='#1e293b'),
        yaxis=dict(showgrid=False),
        height=300
    )
    return fig

def plot_threat_trend(alerts_list):
    """Generates a high-quality line chart showing threats logged over time."""
    if not alerts_list:
        fig = go.Figure()
        return fig
        
    df = pd.DataFrame(alerts_list)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Resample or group by timestamp bucket.
    # For live monitoring, grouping by 10-second intervals or 1-minute intervals is perfect.
    df = df.set_index('timestamp')
    trend_df = df.resample('10S').count()['id'].reset_index()
    trend_df.columns = ['Time', 'Alert Count']
    
    fig = go.Figure(data=[go.Scatter(
        x=trend_df['Time'],
        y=trend_df['Alert Count'],
        mode='lines+markers',
        line=dict(color='#00F0FF', width=3),
        marker=dict(size=6, color='#FF3D68'),
        fill='tozeroy',
        fillcolor='rgba(0, 240, 255, 0.15)'
    )])
    
    fig.update_layout(
        xaxis_title="Time Frame (10s intervals)",
        yaxis_title="Alert Volume",
        margin=dict(t=30, b=30, l=10, r=10),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#E2E8F0',
        xaxis=dict(showgrid=True, gridcolor='#1e293b'),
        yaxis=dict(showgrid=True, gridcolor='#1e293b'),
        height=320
    )
    return fig

def plot_confusion_matrix_plotly(pipeline, X_val, y_val):
    """Plots interactive confusion matrix heatmap from the trained pipeline."""
    y_pred = pipeline.predict(X_val)
    labels = list(pipeline.classes_)
    
    cm = confusion_matrix(y_val, y_pred, labels=labels)
    
    # Normalized confusion matrix
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    cm_norm = np.nan_to_num(cm_norm)  # Clean division by zero if class empty
    
    fig = go.Figure(data=go.Heatmap(
        z=cm_norm,
        x=labels,
        y=labels,
        hoverongaps=False,
        colorscale='Viridis',
        zmin=0, zmax=1,
        text=[[f"Count: {cm[i][j]}<br>Ratio: {cm_norm[i][j]:.2%}" for j in range(len(labels))] for i in range(len(labels))],
        hoverinfo='text'
    ))
    
    fig.update_layout(
        title="Confusion Matrix (Normalized)",
        xaxis_title="Predicted Threat Class",
        yaxis_title="True Threat Class",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#E2E8F0',
        margin=dict(t=50, b=30, l=30, r=10),
        height=380
    )
    return fig

def plot_feature_importance_plotly(pipeline):
    """Extracts feature importances from pipeline and plots them."""
    classifier = pipeline.named_steps['classifier']
    preprocessor = pipeline.named_steps['preprocessor']
    
    importances = classifier.feature_importances_
    
    # Dynamically extract feature names after preprocessing
    cat_encoder = preprocessor.named_transformers_['cat'].named_steps['onehot']
    cat_features = list(cat_encoder.get_feature_names_out(['protocol']))
    
    feature_names = NUMERIC_FEATURES + cat_features
    
    # Sort importances
    indices = np.argsort(importances)
    
    sorted_names = [feature_names[i] for i in indices]
    sorted_importances = [importances[i] for i in indices]
    
    fig = go.Figure(data=[go.Bar(
        x=sorted_importances,
        y=sorted_names,
        orientation='h',
        marker=dict(color='#00F0FF', line=dict(color='#0e1117', width=1))
    )])
    
    fig.update_layout(
        title="Classifier Feature Importance",
        xaxis_title="Gini Importance Score",
        yaxis_title="Feature Name",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#E2E8F0',
        margin=dict(t=50, b=30, l=30, r=10),
        xaxis=dict(showgrid=True, gridcolor='#1e293b'),
        height=380
    )
    return fig
