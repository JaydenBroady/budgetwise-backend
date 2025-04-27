from app import app
from models import db, Transaction
from datetime import datetime

with app.app_context():
    sample_transactions = [
        {"amount": 113.92, "category": "Groceries", "type": "income", "description": "Test Transaction 1", "date": "2025-04-07"},
        {"amount": 85.67, "category": "Groceries", "type": "expense", "description": "Test Transaction 2", "date": "2025-04-16"},
        {"amount": 80.75, "category": "Subscription", "type": "expense", "description": "Test Transaction 3", "date": "2025-03-24"},
        {"amount": 132.65, "category": "Groceries", "type": "income", "description": "Test Transaction 4", "date": "2025-04-05"},
        {"amount": 127.75, "category": "Transport", "type": "expense", "description": "Test Transaction 5", "date": "2025-04-03"},
        {"amount": 117.78, "category": "Transport", "type": "expense", "description": "Test Transaction 6", "date": "2025-03-31"},
        {"amount": 84.21, "category": "Food", "type": "expense", "description": "Test Transaction 7", "date": "2025-04-01"},
        {"amount": 64.1, "category": "Subscription", "type": "expense", "description": "Test Transaction 8", "date": "2025-04-05"},
        {"amount": 57.3, "category": "Utilities", "type": "income", "description": "Test Transaction 9", "date": "2025-03-30"},
        {"amount": 84.58, "category": "Utilities", "type": "income", "description": "Test Transaction 10", "date": "2025-04-10"},
        {"amount": 89.91, "category": "Utilities", "type": "expense", "description": "Recurring Utilities 1", "date": "2025-04-16", "is_recurring": True, "recurrence": "weekly", "next_due_date": "2025-04-16"},
        {"amount": 93.11, "category": "Utilities", "type": "expense", "description": "Recurring Utilities 2", "date": "2025-04-16", "is_recurring": True, "recurrence": "weekly", "next_due_date": "2025-04-23"},
        {"amount": 55.57, "category": "Utilities", "type": "expense", "description": "Recurring Utilities 3", "date": "2025-04-16", "is_recurring": True, "recurrence": "weekly", "next_due_date": "2025-04-30"},
        {"amount": 52.39, "category": "Subscription", "type": "expense", "description": "Recurring Subscription 4", "date": "2025-04-16", "is_recurring": True, "recurrence": "weekly", "next_due_date": "2025-05-07"},
        {"amount": 91.9, "category": "Subscription", "type": "expense", "description": "Recurring Subscription 5", "date": "2025-04-16", "is_recurring": True, "recurrence": "weekly", "next_due_date": "2025-05-14"},
    ]

    for tx in sample_transactions:
        t = Transaction(
            amount=tx["amount"],
            category=tx["category"],
            type=tx["type"],
            description=tx["description"],
            date=datetime.strptime(tx["date"], "%Y-%m-%d"),
            user_id=1,
            is_recurring=tx.get("is_recurring", False),
            recurrence=tx.get("recurrence"),
            next_due_date=datetime.strptime(tx["next_due_date"], "%Y-%m-%d") if tx.get("next_due_date") else None
        )
        db.session.add(t)

    db.session.commit()
    print("✅ Sample transactions added!")
