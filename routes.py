from flask import Blueprint, request, jsonify, Response
from models import User, db, Transaction, Budget
from datetime import datetime, timedelta
from collections import defaultdict
from fpdf import FPDF
import csv
import io
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

auth = Blueprint('auth', __name__)

# Register route
@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 409
    user = User(email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# Login route
@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=str(user.id))   #forces it to create a string 

        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Add a transaction
@auth.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    user_id = get_jwt_identity()
    data = request.get_json()
    transaction = Transaction(
        amount=data['amount'],
        category=data['category'],
        type=data['type'],
        description=data.get('description', ''),
        date=datetime.strptime(data['date'], '%Y-%m-%d'),
        user_id=user_id,
        is_recurring=data.get('is_recurring', False),
        recurrence=data.get('recurrence'),
        next_due_date=datetime.strptime(data['next_due_date'], '%Y-%m-%d') if data.get('next_due_date') else None
    )
    db.session.add(transaction)
    db.session.commit()
    return jsonify({'message': 'Transaction added successfully'}), 201

# Get transactions
@auth.route('/transactions', methods=['GET'])
@jwt_required()
def get_user_transactions():
    user_id = get_jwt_identity()
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    category = request.args.get('category')
    txn_type = request.args.get('type')  # income or expense
    keyword = request.args.get('description')

    query = Transaction.query.filter_by(user_id=user_id)

    if start_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Transaction.date >= start)
        except ValueError:
            return jsonify({'error': 'Invalid start date format (use YYYY-MM-DD)'}), 400

    if end_date:
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(Transaction.date <= end)
        except ValueError:
            return jsonify({'error': 'Invalid end date format (use YYYY-MM-DD)'}), 400

    if category:
        query = query.filter(Transaction.category.ilike(f"%{category}%"))
    
    if txn_type:
        query = query.filter(Transaction.type == txn_type)

    if keyword:
        query = query.filter(Transaction.description.ilike(f"%{keyword}%"))

    transactions = query.order_by(Transaction.date.desc()).all()

    result = []
    for t in transactions:
        result.append({
            'id': t.id,
            'amount': t.amount,
            'category': t.category,
            'type': t.type,
            'description': t.description,
            'date': t.date.strftime('%Y-%m-%d'),
            'is_recurring': t.is_recurring,
            'recurrence': t.recurrence,
            'next_due_date': t.next_due_date.strftime('%Y-%m-%d') if t.next_due_date else None
        })

    return jsonify(result), 200


# Export transactions as CSV
@auth.route('/transactions/export', methods=['GET'])
@jwt_required()
def export_transactions():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Amount', 'Category', 'Type', 'Description', 'Date'])

    for t in transactions:
        writer.writerow([
            t.id, t.amount, t.category, t.type, t.description, t.date.strftime('%Y-%m-%d')
        ])

    output.seek(0)
    return Response(output, mimetype='text/csv', headers={
        'Content-Disposition': f'attachment; filename=transactions_user_{user_id}.csv'
    })

# Export transactions as PDF
@auth.route('/transactions/export-pdf', methods=['GET'])
@jwt_required()
def export_transactions_pdf():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Transaction History", ln=True, align='C')
    pdf.ln(10)

    for t in transactions:
        line = f"{t.date.strftime('%Y-%m-%d')} | {t.type.capitalize()} | {t.category} | £{t.amount} | {t.description}"
        pdf.cell(200, 10, txt=line, ln=True)

    response = Response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=transactions_user_{user_id}.pdf'
    return response

# Update transaction
@auth.route('/transactions/<int:transaction_id>', methods=['PUT'])
@jwt_required()
def update_transaction(transaction_id):
    data = request.get_json()
    transaction = Transaction.query.get(transaction_id)
    user_id = get_jwt_identity()

    if not transaction or transaction.user_id != user_id:
        return jsonify({'message': 'Transaction not found or unauthorized'}), 404

    transaction.amount = data.get('amount', transaction.amount)
    transaction.category = data.get('category', transaction.category)
    transaction.type = data.get('type', transaction.type)
    transaction.description = data.get('description', transaction.description)
    if 'date' in data:
        transaction.date = datetime.strptime(data['date'], '%Y-%m-%d')
    transaction.is_recurring = data.get('is_recurring', transaction.is_recurring)
    transaction.recurrence = data.get('recurrence', transaction.recurrence)
    if data.get('next_due_date'):
        transaction.next_due_date = datetime.strptime(data['next_due_date'], '%Y-%m-%d')

    db.session.commit()
    return jsonify({'message': 'Transaction updated successfully'}), 200

# Delete transaction
@auth.route('/transactions/<int:transaction_id>', methods=['DELETE'])
@jwt_required()
def delete_transaction(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    user_id = get_jwt_identity()

    if not transaction or transaction.user_id != user_id:
        return jsonify({'message': 'Transaction not found or unauthorized'}), 404

    db.session.delete(transaction)
    db.session.commit()
    return jsonify({'message': 'Transaction deleted successfully'}), 200

# Summary (income, expenses, balance)
@auth.route('/summary', methods=['GET'])
@jwt_required()
def get_summary():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expense = sum(t.amount for t in transactions if t.type == 'expense')
    balance = total_income - total_expense

    return jsonify({
        'income': total_income,
        'expenses': total_expense,
        'balance': balance
    }), 200

# Summary by category
@auth.route('/summary/categories', methods=['GET'])
@jwt_required()
def get_category_summary():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    category_totals = {}
    for t in transactions:
        key = f"{t.type}:{t.category}"
        category_totals[key] = category_totals.get(key, 0) + t.amount

    income_breakdown = {}
    expense_breakdown = {}
    for key, total in category_totals.items():
        t_type, category = key.split(":")
        if t_type == "income":
            income_breakdown[category] = total
        else:
            expense_breakdown[category] = total

    return jsonify({
        "income_by_category": income_breakdown,
        "expense_by_category": expense_breakdown
    }), 200

# Set or update a budget
@auth.route('/budget', methods=['POST'])
@jwt_required()
def set_budget():
    user_id = get_jwt_identity()
    data = request.get_json()
    budget = Budget.query.filter_by(user_id=user_id, category=data['category']).first()

    if budget:
        budget.limit = data['limit']
    else:
        budget = Budget(user_id=user_id, category=data['category'], limit=data['limit'])
        db.session.add(budget)

    db.session.commit()
    return jsonify({'message': 'Budget set successfully'}), 200

# Get budget status
@auth.route('/budget', methods=['GET'])
@jwt_required()
def get_budget_status():
    user_id = get_jwt_identity()
    budgets = Budget.query.filter_by(user_id=user_id).all()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    summary = []

    for budget in budgets:
        spent = sum(t.amount for t in transactions if t.category == budget.category and t.type == 'expense')
        remaining = budget.limit - spent

        summary.append({
            'category': budget.category,
            'limit': budget.limit,
            'spent': spent,
            'remaining': remaining
        })

    return jsonify(summary), 200

# Monthly summary route
@auth.route('/summary/monthly', methods=['GET'])
@jwt_required()
def monthly_summary():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    monthly_data = defaultdict(lambda: {"income": 0, "expenses": 0, "balance": 0})

    for t in transactions:
        month = t.date.strftime('%Y-%m')
        if t.type == 'income':
            monthly_data[month]["income"] += t.amount
        elif t.type == 'expense':
            monthly_data[month]["expenses"] += t.amount

        monthly_data[month]["balance"] = (
            monthly_data[month]["income"] - monthly_data[month]["expenses"]
        )

    return jsonify(monthly_data), 200

# Recurring reminders
@auth.route('/reminders', methods=['GET'])
@jwt_required()
def get_upcoming_reminders():
    user_id = get_jwt_identity()
    today = datetime.today()
    upcoming = Transaction.query.filter(
        Transaction.user_id == user_id,
        Transaction.is_recurring == True,
        Transaction.next_due_date != None,
        Transaction.next_due_date >= today
    ).order_by(Transaction.next_due_date).all()

    reminders = []
    for t in upcoming:
        reminders.append({
            'id': t.id,
            'amount': t.amount,
            'category': t.category,
            'description': t.description,
            'recurrence': t.recurrence,
            'next_due_date': t.next_due_date.strftime('%Y-%m-%d') if t.next_due_date else None
        })

    return jsonify(reminders), 200

# Top spending categories
@auth.route('/summary/top-categories', methods=['GET'])
@jwt_required()
def top_spending_categories():
    from sqlalchemy import func
    user_id = get_jwt_identity()
    top_categories = (
        db.session.query(Transaction.category, func.sum(Transaction.amount))
        .filter_by(user_id=user_id, type='expense')
        .group_by(Transaction.category)
        .order_by(func.sum(Transaction.amount).desc())
        .limit(5)
        .all()
    )

    top_categories_data = [
        {'category': cat, 'total': total} for cat, total in top_categories
    ]

    return jsonify({'top_categories': top_categories_data}), 200
