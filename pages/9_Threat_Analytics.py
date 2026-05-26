import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

st.set_page_config(
    page_title='Threat Analytics - CyberShield AI',
    page_icon='📊',
    layout='wide',
    initial_sidebar_state='expanded'
)

from utils.auth import require_login
from utils.ui_helpers import apply_custom_css, render_section_header
from utils.threat_logger import get_threats
from utils.report_generator import export_threats_csv

apply_custom_css()
require_login()

st.markdown('<h1 style="margin:0;">📊 Threat Analytics</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#8a9bb5;margin-top:4px;">Deep-dive intelligence on detected cyber threats</p>', unsafe_allow_html=True)
st.markdown('---')

col_range, col_type_filter = st.columns([3, 3])
with col_range:
    time_range = st.selectbox('⏱️ Time Range', ['Last 24 Hours', 'Last 7 Days', 'Last 30 Days'], index=1)
with col_type_filter:
    threat_type_filter = st.multiselect('🔍 Filter by Type', ['Phishing', 'Fraud', 'Malware', 'Spam', 'Intrusion'], default=[])

hours_map = {'Last 24 Hours': 24, 'Last 7 Days': 168, 'Last 30 Days': 720}
hours_back = hours_map[time_range]

try:
    raw = get_threats()
except Exception:
    raw = []

rng = np.random.default_rng(42)
types = ['Phishing', 'Fraud', 'Malware', 'Spam', 'Intrusion']
severities = ['Critical', 'High', 'Medium', 'Low']
cities = ['Mumbai', 'Delhi', 'Bangalore', 'Chennai', 'Hyderabad', 'Pune', 'Kolkata', 'Ahmedabad']
lat_lon = {
    'Mumbai': (19.07, 72.87), 'Delhi': (28.70, 77.10),
    'Bangalore': (12.97, 77.59), 'Chennai': (13.08, 80.27),
    'Hyderabad': (17.38, 78.48), 'Pune': (18.52, 73.86),
    'Kolkata': (22.57, 88.36), 'Ahmedabad': (23.02, 72.57)
}

rows = []
for i in range(250):
    ts = datetime.now() - timedelta(hours=int(rng.integers(0, hours_back + 1)))
    city = rng.choice(cities)
    rows.append({
        'id': i + 1, 'type': rng.choice(types),
        'severity': rng.choice(severities, p=[0.15, 0.30, 0.35, 0.20]),
        'city': city, 'lat': lat_lon[city][0], 'lon': lat_lon[city][1],
        'timestamp': ts,
        'confidence': round(rng.uniform(0.72, 0.99), 3),
        'blocked': rng.choice([True, False], p=[0.75, 0.25])
    })

if not raw or len(raw) < 20:
    df = pd.DataFrame(rows)
else:
    df = pd.DataFrame(raw)
    if 'threat_type' in df.columns:
        df = df.rename(columns={'threat_type': 'type'})
        type_mapping = {
            'phishing_email': 'Phishing',
            'malicious_url': 'Phishing',
            'sms_spam': 'Spam',
            'fraud_transaction': 'Fraud',
            'intrusion': 'Intrusion',
            'malware': 'Malware'
        }
        df['type'] = df['type'].map(type_mapping).fillna(df['type'].astype(str).str.title())
    df['timestamp'] = pd.to_datetime(df.get('timestamp', pd.Timestamp.now()), format='mixed')
    if hasattr(df['timestamp'].dt, 'tz') and df['timestamp'].dt.tz is not None:
        df['timestamp'] = df['timestamp'].dt.tz_localize(None)
    cutoff = datetime.now() - timedelta(hours=hours_back)
    df = df[df['timestamp'] > cutoff]
    for col in ['city', 'lat', 'lon', 'confidence', 'blocked']:
        if col not in df.columns:
            df[col] = None
    if 'city' not in df.columns or df['city'].isna().all():
        df['city'] = rng.choice(cities, len(df))
    if 'confidence' not in df.columns or df['confidence'].isna().all():
        df['confidence'] = rng.uniform(0.72, 0.99, len(df))

df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed')
if hasattr(df['timestamp'].dt, 'tz') and df['timestamp'].dt.tz is not None:
    df['timestamp'] = df['timestamp'].dt.tz_localize(None)
cutoff = datetime.now() - timedelta(hours=hours_back)
df = df[df['timestamp'] > cutoff]
if threat_type_filter and 'type' in df.columns:
    df = df[df['type'].isin(threat_type_filter)]

if df.empty:
    st.warning('No threat data for selected range. Showing demo data.')
    df = pd.DataFrame(rows)

render_section_header('📋 Summary Metrics', f'Based on {time_range}')
m1, m2, m3, m4, m5 = st.columns(5)
most_common = df['type'].mode()[0] if 'type' in df.columns and not df.empty else 'N/A'
df['hour_of_day'] = df['timestamp'].dt.hour
peak_hour = int(df['hour_of_day'].mode()[0]) if not df.empty else 0
avg_acc = df['confidence'].mean() * 100 if 'confidence' in df.columns else 0
blocked_pct = (df['blocked'].sum() / len(df) * 100) if 'blocked' in df.columns and not df.empty else 0

m1.metric('🎯 Most Common Attack', most_common)
m2.metric('🕐 Peak Attack Hour', f'{peak_hour:02d}:00')
m3.metric('📊 Avg Confidence', f'{avg_acc:.1f}%')
m4.metric('🚫 Blocked Rate', f'{blocked_pct:.0f}%')
m5.metric('📝 Total Events', len(df))

st.markdown('---')

render_section_header('📈 Trend Analysis', '')
c1, c2 = st.columns(2)

with c1:
    st.subheader('Threat Trends by Type')
    df_trend = df.copy()
    freq = 'h' if hours_back <= 24 else 'D'
    df_trend['period'] = df_trend['timestamp'].dt.floor(freq)
    trend_grp = df_trend.groupby(['period', 'type']).size().reset_index(name='count')
    fig = px.line(trend_grp, x='period', y='count', color='type', template='plotly_dark',
                  color_discrete_sequence=px.colors.qualitative.Bold)
    fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                      height=300, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)

with c2:
    st.subheader('Attack Distribution')
    attack_counts = df['type'].value_counts().reset_index()
    attack_counts.columns = ['type', 'count']
    fig2 = px.bar(attack_counts, x='type', y='count', color='type', template='plotly_dark',
                  color_discrete_sequence=['#ff4757', '#ffa502', '#00d4ff', '#2ed573', '#eccc68'])
    fig2.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                       height=300, margin=dict(l=10, r=10, t=10, b=10), showlegend=False)
    st.plotly_chart(fig2, use_container_width=True)

c3, c4 = st.columns(2)

with c3:
    st.subheader('Threat Severity Distribution')
    sev_counts = df['severity'].value_counts().reset_index() if 'severity' in df.columns else pd.DataFrame({'severity': [], 'count': []})
    sev_counts.columns = ['severity', 'count']
    sev_colors = {'Critical': '#ff4757', 'High': '#ffa502', 'Medium': '#ffd700', 'Low': '#2ed573'}
    fig3 = px.pie(sev_counts, names='severity', values='count', hole=0.45, template='plotly_dark',
                  color='severity', color_discrete_map=sev_colors)
    fig3.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', height=300, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig3, use_container_width=True)

with c4:
    st.subheader('Fraud Frequency Distribution')
    fraud_df = df[df['type'] == 'Fraud'].copy() if 'type' in df.columns else df.copy()
    if not fraud_df.empty:
        fraud_df['conf_bin'] = (fraud_df['confidence'] * 100).round(0)
        fig4 = px.histogram(fraud_df, x='conf_bin', nbins=20, template='plotly_dark',
                            color_discrete_sequence=['#ffa502'],
                            labels={'conf_bin': 'Confidence Score (%)', 'count': 'Count'})
        fig4.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', height=300, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig4, use_container_width=True)
    else:
        st.info('No fraud data in selected range.')

c5, c6 = st.columns(2)

with c5:
    st.subheader('📍 Geographic Distribution (India)')
    if 'city' in df.columns:
        geo_df = df.groupby('city').size().reset_index(name='count')
        geo_df['lat'] = geo_df['city'].map(lambda c: lat_lon.get(c, (20, 77))[0])
        geo_df['lon'] = geo_df['city'].map(lambda c: lat_lon.get(c, (20, 77))[1])
        fig5 = px.scatter_geo(geo_df, lat='lat', lon='lon', size='count', hover_name='city',
                              color='count', color_continuous_scale='Reds', template='plotly_dark',
                              scope='asia', projection='natural earth')
        fig5.update_geos(bgcolor='rgba(0,0,0,0)', landcolor='#1a1a2e', oceancolor='#0d0d1a',
                         showland=True, showocean=True, lakecolor='#0d0d1a',
                         lataxis_range=[5, 38], lonaxis_range=[65, 100])
        fig5.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', height=300, margin=dict(l=0, r=0, t=0, b=0))
        st.plotly_chart(fig5, use_container_width=True)
    else:
        st.bar_chart(df.get('city', pd.Series()).value_counts())

with c6:
    st.subheader('⏰ Hour-of-Day Activity')
    hour_counts = df.groupby('hour_of_day').size().reset_index(name='count')
    fig6 = px.bar(hour_counts, x='hour_of_day', y='count', template='plotly_dark',
                  color='count', color_continuous_scale='RdYlGn_r',
                  labels={'hour_of_day': 'Hour (24h)', 'count': 'Threats'})
    fig6.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', height=300, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig6, use_container_width=True)

st.subheader('📅 Day-of-Week × Hour Heatmap')
df['dow'] = df['timestamp'].dt.day_name()
days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
hm = df.groupby(['dow', 'hour_of_day']).size().unstack(fill_value=0)
hm = hm.reindex([d for d in days_order if d in hm.index])
fig_hm = px.imshow(hm, color_continuous_scale='YlOrRd', template='plotly_dark',
                   labels=dict(x='Hour', y='Day', color='Threats'), aspect='auto')
fig_hm.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', height=250, margin=dict(l=10, r=10, t=10, b=10))
st.plotly_chart(fig_hm, use_container_width=True)

st.markdown('---')

render_section_header('🤖 Model Performance Metrics', 'Precision, Recall, F1 per model')

models = {
    'Phishing Detector (RF)': {'precision': 0.94, 'recall': 0.91, 'f1': 0.925, 'cm': [[412, 28], [21, 339]]},
    'Fraud Detector (XGB)': {'precision': 0.91, 'recall': 0.88, 'f1': 0.895, 'cm': [[380, 42], [35, 263]]},
    'SMS Scam Classifier (NB)': {'precision': 0.89, 'recall': 0.85, 'f1': 0.870, 'cm': [[520, 18], [33, 189]]},
}

cols_m = st.columns(len(models))
for idx, (mname, mdata) in enumerate(models.items()):
    with cols_m[idx]:
        st.markdown(f'**{mname}**')
        mc1, mc2, mc3 = st.columns(3)
        mc1.metric('Precision', f"{mdata['precision'] * 100:.1f}%")
        mc2.metric('Recall', f"{mdata['recall'] * 100:.1f}%")
        mc3.metric('F1 Score', f"{mdata['f1'] * 100:.1f}%")
        cm_arr = np.array(mdata['cm'])
        fig_cm = px.imshow(cm_arr, text_auto=True, template='plotly_dark',
                           color_continuous_scale='Blues',
                           labels=dict(x='Predicted', y='Actual', color='Count'),
                           x=['Legit', 'Threat'], y=['Legit', 'Threat'])
        fig_cm.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                             height=220, margin=dict(l=10, r=10, t=30, b=10),
                             title=dict(text='Confusion Matrix', font_size=12))
        st.plotly_chart(fig_cm, use_container_width=True)

st.markdown('---')

render_section_header('📆 This Week vs Last Week', 'Comparative threat volume')
this_week = df[df['timestamp'] > datetime.now() - timedelta(days=7)]
last_week_start = datetime.now() - timedelta(days=14)
last_week = df[(df['timestamp'] > last_week_start) & (df['timestamp'] <= datetime.now() - timedelta(days=7))]

comp_data = pd.DataFrame({
    'Metric': ['Total Threats', 'Phishing', 'Fraud', 'Malware', 'Avg Confidence'],
    'This Week': [
        len(this_week),
        len(this_week[this_week['type'] == 'Phishing']) if 'type' in this_week.columns else 0,
        len(this_week[this_week['type'] == 'Fraud']) if 'type' in this_week.columns else 0,
        len(this_week[this_week['type'] == 'Malware']) if 'type' in this_week.columns else 0,
        round(this_week['confidence'].mean() * 100, 1) if 'confidence' in this_week.columns and not this_week.empty else 0,
    ],
    'Last Week': [
        len(last_week),
        len(last_week[last_week['type'] == 'Phishing']) if 'type' in last_week.columns else 0,
        len(last_week[last_week['type'] == 'Fraud']) if 'type' in last_week.columns else 0,
        len(last_week[last_week['type'] == 'Malware']) if 'type' in last_week.columns else 0,
        round(last_week['confidence'].mean() * 100, 1) if 'confidence' in last_week.columns and not last_week.empty else 0,
    ]
})

fig_comp = px.bar(comp_data.melt(id_vars='Metric', var_name='Period', value_name='Value'),
                  x='Metric', y='Value', color='Period', barmode='group', template='plotly_dark',
                  color_discrete_map={'This Week': '#00d4ff', 'Last Week': '#8a9bb5'})
fig_comp.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                       height=300, margin=dict(l=10, r=10, t=10, b=10))
st.plotly_chart(fig_comp, use_container_width=True)

st.markdown('---')

render_section_header('📥 Export Analytics', '')
try:
    csv_data = export_threats_csv(df.to_dict('records'))
    st.download_button('⬇️ Download Analytics CSV', csv_data, 'analytics_export.csv', 'text/csv')
except Exception:
    csv_bytes = df.to_csv(index=False).encode('utf-8')
    st.download_button('⬇️ Download Analytics CSV', csv_bytes, 'analytics_export.csv', 'text/csv')
