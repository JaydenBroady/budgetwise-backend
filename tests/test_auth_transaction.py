# tests/test_insights.py

import os
import sys
import pytest

# Add project root (where app.py lives) to import path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app import app, db
from models import Transaction, Budget
from datetime import datetime

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
    client = app.test_client()
    yield client
    with app.app_context():
        db.drop_all()

def register_and_login(client):
    client.post('/register', json={'email':'insights@test.com','password':'Pass123'})
    rv = client.post('/login', json={'email':'insights@test.com','password':'Pass123'})
    token = rv.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}

def test_spending_forecast(client):
    headers = register_and_login(client)
    # Seed three months of expenses in category 'A'
    txns = [
        {'amount': 100, 'category': 'A', 'type': 'expense', 'description': '', 'date': '2025-01-15'},
        {'amount': 200, 'category': 'A', 'type': 'expense', 'description': '', 'date': '2025-02-15'},
        {'amount': 300, 'category': 'A', 'type': 'expense', 'description': '', 'date': '2025-03-15'},
    ]
    for t in txns:
        client.post('/transactions', json=t, headers=headers)

    rv = client.get('/insights/forecast', headers=headers)
    assert rv.status_code == 200
    data = rv.get_json()
    # Average of 100,200,300 = 200.0
    assert data.get('A') == pytest.approx(200.0)

def test_anomaly_detection(client):
    headers = register_and_login(client)
    # Seed normal and one outlier in category 'B'
    normals = [10, 12, 11, 13]
    for amt in normals:
        client.post('/transactions', json={
            'amount': amt, 'category': 'B', 'type': 'expense',
            'description': '', 'date': '2025-04-01'
        }, headers=headers)
    # Outlier
    rv_tx = client.post('/transactions', json={
        'amount': 50, 'category': 'B', 'type': 'expense',
        'description': 'outlier', 'date': '2025-04-02'
    }, headers=headers)
    outlier_id = rv_tx.get_json()['transaction']['id']

    rv = client.get('/insights/anomalies', headers=headers)
    assert rv.status_code == 200
    anomalies = rv.get_json()
    # Should detect exactly the outlier transaction
    assert any(a['id'] == outlier_id and a['amount'] == 50 for a in anomalies)
    # No false positives for normals
    ids = [a['id'] for a in anomalies]
    for amt, tid in zip(normals, range(len(normals))):
        assert amt not in [a['amount'] for a in anomalies]

def test_budget_breach_alerts_and_recommendations(client):
    headers = register_and_login(client)
    # Seed three months of expenses in category 'C'
    for d, amt in [('2025-01-10',100),('2025-02-10',200),('2025-03-10',300)]:
        client.post('/transactions', json={
            'amount': amt, 'category': 'C', 'type': 'expense',
            'description': '', 'date': d
        }, headers=headers)
    # Set budget lower than forecasted (forecast = avg(100,200,300)=200)
    client.post('/budget', json={'category':'C','limit':150}, headers=headers)

    # Alerts
    rv_alerts = client.get('/insights/alerts', headers=headers)
    assert rv_alerts.status_code == 200
    alerts = rv_alerts.get_json()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert['category'] == 'C'
    assert alert['forecasted_spend'] == pytest.approx(200.0)
    assert alert['budget_limit'] == 150
    assert alert['excess'] == pytest.approx(50.0)

    # Recommendations
    rv_recs = client.get('/insights/recommendations', headers=headers)
    assert rv_recs.status_code == 200
    recs = rv_recs.get_json()
    assert len(recs) == 1
    rec = recs[0]
    # excess 50 over 200 => 25%
    assert rec['suggested_cut_percentage'] == pytest.approx(25.0)
    assert 'Reduce spending by ~25.0%' in rec['message']
