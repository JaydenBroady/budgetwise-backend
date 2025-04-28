# BudgetWise Backend

![CI](https://github.com/JaydenBroady/budgetwise-backend/actions/workflows/python-app.yml/badge.svg)

A Flask-based budgeting API with JWT auth, SQLAlchemy models, ML insights, and Swagger docs.

## Quickstart

```bash
git clone https://github.com/JaydenBroady/budgetwise-backend.git
cd budgetwise-backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.py FLASK_ENV=development
flask run
