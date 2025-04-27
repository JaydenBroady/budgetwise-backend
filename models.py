from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash  # Corrected import
from datetime import datetime  # For default timestamp handling

db = SQLAlchemy()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # Method to hash the password before storing it
    def set_password(self, password):
        # Explicitly specify the hashing method (pbkdf2:sha256)
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    # Method to check the provided password against the stored hash
    def check_password(self, password):
        return check_password_hash(self.password, password)

# Transaction Model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # "income" or "expense"
    description = db.Column(db.String(255))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_recurring = db.Column(db.Boolean, default=False)
    recurrence = db.Column(db.String(20), nullable=True)  # "daily", "weekly", "monthly"
    next_due_date = db.Column(db.DateTime, nullable=True)

    # Establish a relationship with User model
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

# Budget Model
class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    limit = db.Column(db.Float, nullable=False)

    # Establish a relationship with User model
    user = db.relationship('User', backref=db.backref('budgets', lazy=True))
