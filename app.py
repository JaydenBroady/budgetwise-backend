import os
import io
import csv
import logging
import statistics
from datetime import datetime
from collections import defaultdict

from flask import Flask, jsonify, request, Blueprint, Response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from fpdf import FPDF
from flasgger import Swagger, LazyJSONEncoder

from models import db, User, Transaction, Budget

# Load environment variables
load_dotenv()

# Create and configure the Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.config['SQLALCHEMY_DATABASE_URI']        = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key                              = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['JWT_SECRET_KEY']                = os.getenv('JWT_SECRET_KEY', 'supersecretjwtkey')
app.config['JWT_TOKEN_LOCATION']            = ['headers']
app.config['JWT_HEADER_NAME']               = 'Authorization'
app.config['JWT_HEADER_TYPE']               = 'Bearer'

# Use Flasgger's JSON encoder
app.json_encoder = LazyJSONEncoder

# Swagger / OpenAPI configuration
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "BudgetWise API",
        "description": "Interactive API docs for the BudgetWise backend",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'"
        }
    },
    "security": [{"Bearer": []}]
}
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs/"
}
Swagger(app, template=swagger_template, config=swagger_config)

# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Auth Blueprint ---
auth = Blueprint('auth', __name__)

@auth.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: user
        schema:
          required: [email, password]
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      201:
        description: User registered successfully
      400:
        description: Missing email or password
      409:
        description: Email already exists
    """
    data = request.get_json() or {}
    email    = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 409
    hashed = generate_password_hash(password, method='pbkdf2:sha256')
    user   = User(email=email, password=hashed)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@auth.route('/login', methods=['POST'])
def login():
    """
    Obtain JWT access token.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: credentials
        schema:
          required: [email, password]
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: Returns access token
      400:
        description: Missing email or password
      401:
        description: Invalid credentials
    """
    data = request.get_json() or {}
    email    = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=str(user.id))
    return jsonify({'access_token': access_token}), 200

@auth.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    """
    Create a new transaction.
    ---
    tags:
      - Transactions
    security:
      - Bearer: []
    parameters:
      - in: body
        name: transaction
        schema:
          required: [amount, category, type, date]
          properties:
            amount:
              type: number
            category:
              type: string
            type:
              type: string
              enum: [income, expense]
            description:
              type: string
            date:
              type: string
              format: date
    responses:
      201:
        description: Transaction added
      400:
        description: Validation error
    """
    user_id = int(get_jwt_identity())
    data    = request.get_json() or {}
    for field in ('amount', 'category', 'type', 'date'):
        if field not in data:
            return jsonify({'error': f"Missing field: {field}"}), 400
    try:
        amount = float(data['amount'])
        if amount <= 0:
            raise ValueError()
    except ValueError:
        return jsonify({'error': 'Amount must be a positive number'}), 400
    txn_type = data['type']
    if txn_type not in ('income', 'expense'):
        return jsonify({'error': 'Type must be "income" or "expense"'}), 400
    try:
        date_obj = datetime.strptime(data['date'], '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format, use YYYY-MM-DD'}), 400

    txn = Transaction(
        amount     = amount,
        category   = data['category'],
        type       = txn_type,
        description= data.get('description', ''),
        date       = date_obj,
        user_id    = user_id
    )
    db.session.add(txn)
    db.session.commit()
    return jsonify({
        'message': 'Transaction added',
        'transaction': {
            'id': txn.id,
            'amount': txn.amount,
            'category': txn.category,
            'type': txn.type,
            'description': txn.description,
            'date': txn.date.strftime('%Y-%m-%d')
        }
    }), 201

@auth.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    """
    Retrieve all transactions for the current user.
    ---
    tags:
      - Transactions
    security:
      - Bearer: []
    responses:
      200:
        description: List of transactions
      404:
        description: No transactions found
    """
    user_id = int(get_jwt_identity())
    txns    = Transaction.query.filter_by(user_id=user_id).all()
    if not txns:
        return jsonify({'message': 'No transactions found'}), 404
    return jsonify([{
        'id': t.id,
        'amount': t.amount,
        'category': t.category,
        'type': t.type,
        'description': t.description,
        'date': t.date.strftime('%Y-%m-%d')
    } for t in txns]), 200

@auth.route('/transactions/<int:transaction_id>', methods=['PUT'])
@jwt_required()
def update_transaction(transaction_id):
    """
    Update a transaction.
    ---
    tags:
      - Transactions
    security:
      - Bearer: []
    parameters:
      - in: path
        name: transaction_id
        type: integer
        required: true
      - in: body
        name: updates
        schema:
          properties:
            amount:
              type: number
            category:
              type: string
            type:
              type: string
            description:
              type: string
            date:
              type: string
              format: date
    responses:
      200:
        description: Transaction updated
      404:
        description: Not found or unauthorized
    """
    user_id = int(get_jwt_identity())
    txn     = Transaction.query.get(transaction_id)
    if not txn or txn.user_id != user_id:
        return jsonify({'message': 'Transaction not found or unauthorized'}), 404
    data = request.get_json() or {}
    if 'amount' in data:
        try:
            amt = float(data['amount'])
            if amt <= 0:
                raise ValueError()
            txn.amount = amt
        except ValueError:
            return jsonify({'error': 'Amount must be a positive number'}), 400
    if 'category' in data:
        txn.category = data['category']
    if 'type' in data:
        if data['type'] not in ('income', 'expense'):
            return jsonify({'error': 'Type must be "income" or "expense"'}), 400
        txn.type = data['type']
    if 'description' in data:
        txn.description = data['description']
    if 'date' in data:
        try:
            txn.date = datetime.strptime(data['date'], '%Y-%m-%d')
        except ValueError:
            return jsonify({'error': 'Invalid date format, use YYYY-MM-DD'}), 400
    db.session.commit()
    return jsonify({'message': 'Transaction updated successfully'}), 200

@auth.route('/transactions/<int:transaction_id>', methods=['DELETE'])
@jwt_required()
def delete_transaction(transaction_id):
    """
    Delete a transaction.
    ---
    tags:
      - Transactions
    security:
      - Bearer: []
    parameters:
      - in: path
        name: transaction_id
        type: integer
        required: true
    responses:
      200:
        description: Deleted successfully
      404:
        description: Not found or unauthorized
    """
    user_id = int(get_jwt_identity())
    txn     = Transaction.query.get(transaction_id)
    if not txn or txn.user_id != user_id:
        return jsonify({'message': 'Transaction not found or unauthorized'}), 404
    db.session.delete(txn)
    db.session.commit()
    return jsonify({'message': 'Transaction deleted successfully'}), 200

@auth.route('/budget', methods=['POST'])
@jwt_required()
def set_budget():
    """
    Set or update a budget for a category.
    ---
    tags:
      - Budgets
    security:
      - Bearer: []
    parameters:
      - in: body
        name: budget
        schema:
          required: [category, limit]
          properties:
            category:
              type: string
            limit:
              type: number
    responses:
      200:
        description: Budget set
      400:
        description: Validation error
    """
    user_id = int(get_jwt_identity())
    data    = request.get_json() or {}
    category = data.get('category')
    limit    = data.get('limit')
    if not category or limit is None:
        return jsonify({'error': 'Category and limit are required'}), 400
    try:
        limit_val = float(limit)
        if limit_val < 0:
            raise ValueError()
    except ValueError:
        return jsonify({'error': 'Limit must be a non-negative number'}), 400
    budget = Budget.query.filter_by(user_id=user_id, category=category).first()
    if budget:
        budget.limit = limit_val
    else:
        budget = Budget(user_id=user_id, category=category, limit=limit_val)
        db.session.add(budget)
    db.session.commit()
    return jsonify({'message': 'Budget set successfully'}), 200

@auth.route('/budget', methods=['GET'])
@jwt_required()
def get_budget_status():
    """
    Get budgets with spent and remaining amounts.
    ---
    tags:
      - Budgets
    security:
      - Bearer: []
    responses:
      200:
        description: List of budgets
    """
    user_id  = int(get_jwt_identity())
    budgets  = Budget.query.filter_by(user_id=user_id).all()
    expenses = Transaction.query.filter_by(user_id=user_id, type='expense').all()
    result   = []
    for b in budgets:
        spent = sum(t.amount for t in expenses if t.category == b.category)
        result.append({
            'category':  b.category,
            'limit':     b.limit,
            'spent':     spent,
            'remaining': b.limit - spent
        })
    return jsonify(result), 200

@auth.route('/transactions/export', methods=['GET'])
@jwt_required()
def export_transactions_csv():
    """
    Export transactions as CSV.
    ---
    tags:
      - Exports
    security:
      - Bearer: []
    responses:
      200:
        description: CSV file
    """
    user_id = int(get_jwt_identity())
    txns    = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date).all()
    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow(['ID','Amount','Category','Type','Description','Date'])
    for t in txns:
        writer.writerow([
            t.id,
            f"{t.amount:.2f}",
            t.category,
            t.type,
            t.description or '',
            t.date.strftime('%Y-%m-%d')
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=transactions_{user_id}.csv'}
    )

@auth.route('/transactions/export-pdf', methods=['GET'])
@jwt_required()
def export_transactions_pdf():
    """
    Export transactions as PDF.
    ---
    tags:
      - Exports
    security:
      - Bearer: []
    responses:
      200:
        description: PDF file
    """
    user_id = int(get_jwt_identity())
    txns    = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date).all()
    pdf     = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Transaction History", ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 10)
    for h, w in [('ID',10),('Amount',20),('Category',30),('Type',20),('Desc',50),('Date',30)]:
        pdf.cell(w, 8, h, border=1)
    pdf.ln()
    pdf.set_font("Arial", size=10)
    for t in txns:
        pdf.cell(10, 8, str(t.id), border=1)
        pdf.cell(20, 8, f"{t.amount:.2f}", border=1)
        pdf.cell(30, 8, t.category[:15], border=1)
        pdf.cell(20, 8, t.type, border=1)
        pdf.cell(50, 8, (t.description or "")[:30], border=1)
        pdf.cell(30, 8, t.date.strftime('%Y-%m-%d'), border=1)
        pdf.ln()
    pdf_data = pdf.output(dest='S').encode('latin-1')
    return Response(
        pdf_data,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename=transactions_{user_id}.pdf'}
    )

@auth.route('/insights/forecast', methods=['GET'])
@jwt_required()
def spending_forecast():
    """
    Spending forecast (3-month moving average).
    ---
    tags:
      - Insights
    security:
      - Bearer: []
    responses:
      200:
        description: Forecast per category
    """
    user_id = int(get_jwt_identity())
    txns    = Transaction.query.filter_by(user_id=user_id, type='expense').all()
    sums    = defaultdict(lambda: defaultdict(float))
    for t in txns:
        sums[t.category][t.date.strftime('%Y-%m')] += t.amount

    forecast = {}
    for cat, monthly in sums.items():
        vals = [v for _, v in sorted(monthly.items())][-3:]
        if vals:
            forecast[cat] = round(sum(vals) / len(vals), 2)
    return jsonify(forecast), 200

@auth.route('/insights/anomalies', methods=['GET'])
@jwt_required()
def anomaly_detection():
    """
    Anomaly detection (> mean + std).
    ---
    tags:
      - Insights
    security:
      - Bearer: []
    responses:
      200:
        description: List of anomalies
    """
    user_id = int(get_jwt_identity())
    txns    = Transaction.query.filter_by(user_id=user_id, type='expense').all()
    by_cat  = defaultdict(list)
    for t in txns:
        by_cat[t.category].append(t.amount)

    anomalies = []
    for cat, amounts in by_cat.items():
        if len(amounts) < 2:
            continue
        mean      = statistics.mean(amounts)
        std       = statistics.stdev(amounts)
        threshold = mean + std
        for t in txns:
            if t.category == cat and t.amount > threshold:
                anomalies.append({
                    'id':        t.id,
                    'amount':    t.amount,
                    'category':  cat,
                    'date':      t.date.strftime('%Y-%m-%d'),
                    'threshold': round(threshold, 2)
                })
    return jsonify(anomalies), 200

@auth.route('/insights/alerts', methods=['GET'])
@jwt_required()
def budget_breach_alerts():
    """
    Budget breach alerts.
    ---
    tags:
      - Insights
    security:
      - Bearer: []
    responses:
      200:
        description: Alerts if forecast > budget
    """
    user_id = int(get_jwt_identity())

    txns = Transaction.query.filter_by(user_id=user_id, type='expense').all()
    sums = defaultdict(lambda: defaultdict(float))
    for t in txns:
        sums[t.category][t.date.strftime('%Y-%m')] += t.amount

    forecast = {}
    for cat, monthly in sums.items():
        vals = [v for _, v in sorted(monthly.items())][-3:]
        if vals:
            forecast[cat] = round(sum(vals) / len(vals), 2)

    budgets = Budget.query.filter_by(user_id=user_id).all()
    alerts  = []
    for b in budgets:
        fval = forecast.get(b.category, 0)
        if fval > b.limit:
            alerts.append({
                'category':         b.category,
                'forecasted_spend': fval,
                'budget_limit':     b.limit,
                'excess':           round(fval - b.limit, 2)
            })
    return jsonify(alerts), 200

@auth.route('/insights/recommendations', methods=['GET'])
@jwt_required()
def savings_recommendations():
    """
    Savings recommendations.
    ---
    tags:
      - Insights
    security:
      - Bearer: []
    responses:
      200:
        description: Suggested cuts
    """
    user_id = int(get_jwt_identity())

    # inline forecast
    txns = Transaction.query.filter_by(user_id=user_id, type='expense').all()
    sums = defaultdict(lambda: defaultdict(float))
    for t in txns:
        sums[t.category][t.date.strftime('%Y-%m')] += t.amount

    forecast = {}
    for cat, monthly in sums.items():
        vals = [v for _, v in sorted(monthly.items())][-3:]
        if vals:
            forecast[cat] = round(sum(vals) / len(vals), 2)

    # inline alerts
    budgets = Budget.query.filter_by(user_id=user_id).all()
    alerts  = []
    for b in budgets:
        fval = forecast.get(b.category, 0)
        if fval > b.limit:
            alerts.append({
                'category':         b.category,
                'forecasted_spend': fval,
                'budget_limit':     b.limit,
                'excess':           round(fval - b.limit, 2)
            })

    recs = []
    for a in alerts:
        cut_pct = round((a['excess'] / a['forecasted_spend']) * 100, 2) if a['forecasted_spend'] else 0
        recs.append({
            'category':                 a['category'],
            'suggested_cut_percentage': cut_pct,
            'message':                  f"Reduce spending by ~{cut_pct}% to meet budget"
        })
    return jsonify(recs), 200

# Register the auth blueprint
app.register_blueprint(auth)

# Home route & error handlers
@app.route('/')
def home():
    return 'BudgetWise Backend is running! 🚀'

@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 Error: {error}")
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(400)
def bad_request_error(error):
    logger.error(f"400 Error: {error}")
    return jsonify({'error': 'Bad request. Please check your input.'}), 400

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"500 Error: {error}")
    return jsonify({'error': 'Internal server error. Something went wrong.'}), 500

# Run server
if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully.")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
    app.run(debug=True)
