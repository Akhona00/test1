from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from paystackapi.paystack import Paystack
from paystackapi.transaction import Transaction
import jwt
from datetime import datetime, timedelta, timezone
import os
import binascii
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
bycrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///CashGaurd.db'
db = SQLAlchemy(app)
app.config['PAYSTACK_SECRET_KEY'] = os.getenv('PAYSTACK_SECRET_KEY', 'your_paystack_secret_key')
#SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

def generate_secret_key(): 
    return binascii.hexlify(os.urandom(24)).decode()
SECRET_KEY = generate_secret_key() 
print(generate_secret_key())

paystack = Paystack(secret_key=app.config['PAYSTACK_SECRET_KEY'])

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        #tokens = request.headers.get("Authorization")
        tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJPd25lcl9pZCI6Mjk5LCJleHAiOjE3MTc2MDM4MDV9.K9sZD9GELWeC_gnsDaBgdK_LRLKo0uOZfS4Ko6eTfd4"
        token = jwt.decode(tok, SECRET_KEY, options={"verify_signature": False}, algorithms="HS256")

        if not token:
            return jsonify({'message': "Token is missing!"}), 403
        try:
            data = request.get_json()
            user = Owners.query.filter_by(Owner_email=data['email']).first()
            print('We are getting what we want')
            if not user:
                return jsonify({'message': 'User not found!'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(user, *args, **kwargs)
    
    return decorated

class Owners(db.Model):
    __tablename__ = 'Owners'
    Owner_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Owner_name = db.Column(db.String(80), nullable=False)
    Owner_email = db.Column(db.String(50), nullable=False, unique=True)
    Owner_password = db.Column(db.LargeBinary, nullable=False)
    Created_at = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))

class Businesses(db.Model):
    __tablename__ = 'businesses'
    Business_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Business_name = db.Column(db.String(80), nullable=False)
    City = db.Column(db.String(50), nullable=False)
    Area_code = db.Column(db.Integer, nullable=False)
    Owner_id = db.Column(db.Integer, db.ForeignKey('owners.Owner_id'), nullable=False)
    Created_at = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))

class Staff(db.Model):
    __tablename__ = 'taff'
    Staff_id = db.Column(db.Integer, primary_key=True)
    Staff_name = db.Column(db.String(50), nullable=False)
    Staff_email = db.Column(db.String(50), nullable=False)
    Staff_password = db.Column(db.LargeBinary, nullable=False)
    Business_id = db.Column(db.Integer, db.ForeignKey('Businesses.Business_id'), nullable=False)
    Created_at = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))

class Inventory(db.Model):
    __tablename__ = 'Inventory'
    Inventory_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Business_id = db.Column(db.Integer, db.ForeignKey('Businesses.Business_id'))
    Item_name = db.Column(db.String(80), nullable=False)
    Quantity = db.Column(db.Integer, nullable=False)
    Price = db.Column(db.Numeric(10,2), nullable=False)
    Created_at = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))
    Updated_at = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc), onupdate=datetime.now(tz=timezone.utc))
    Barcode = db.Column(db.String, nullable=False)

class Sale(db.Model):
    __tablename__ = 'ales'
    Sale_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Business_id = db.Column(db.Integer, db.ForeignKey('Businesses.Business_id'))
    Staff_id = db.Column(db.Integer, db.ForeignKey('Staff.Staff_id'))
    Total_amount = db.Column(db.Numeric(10,2), nullable=False)
    Payment_method = db.Column(db.String(50), nullable=False)
    Sale_date = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))

class SaleItem(db.Model):
    __tablename__ = 'aleitems'
    SaleItem_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Sale_id = db.Column(db.Integer, db.ForeignKey('Sales.Sale_id'), nullable=False)
    Inventory_id = db.Column(db.Integer, db.ForeignKey('Inventory.Inventory_id'))
    Quantity = db.Column(db.Integer, nullable=False)
    Price = db.Column(db.Numeric(10,2), nullable=False)

class BusinessReport(db.Model):
    __tablename__ = 'businessreports'
    Report_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Business_id = db.Column(db.Integer, db.ForeignKey('Businesses.Business_id'))
    Report_date = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))
    Total_sales = db.Column(db.Numeric(10,2), nullable=False)
    Total_profit = db.Column(db.Numeric(10,2), nullable=False)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bycrypt.generate_password_hash(data['password'])
    new_user = Owners(Owner_name=data['name'], Owner_email=data['email'], Owner_password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'})

@app.route("/medium")
@limiter.limit("1/second", override_defaults=False)
def medium():
    return ":|"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = Owners.query.filter_by(Owner_email=data['email']).first()
    if user and bycrypt.check_password_hash(user.Owner_password, data['password']):
        token = jwt.encode({'Owner_id': user.Owner_id, 'exp': datetime.now(tz=timezone.utc) + timedelta(minutes=60)}, SECRET_KEY, algorithm="HS256")
        print(token)
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 403

@app.route('/add_inventory', methods=['POST'])
@token_required
def add_inventory(user):
    data = request.get_json()
    business = Businesses.query.filter_by(Business_id=data['business_id']).first()
    if not business:
        return jsonify({'message': 'Business not found'}), 404
    new_item = Inventory(business_id=data['business_id'], item_name=data['item_name'], quantity=data['quantity'], price=data['price'], barcode=data.get('barcode'))
    db.session.add(new_item)
    db.session.commit()
    return jsonify({'message': 'Item added to inventory'})

@app.route('/process_payment', methods=['POST'])
@token_required
@limiter.limit("5 per minute")
def process_payment(current_user):
    data = request.get_json()
    if not data or 'business_id' not in data or 'total_amount' not in data or 'payment_method' not in data or 'items' not in data:
        return jsonify({'message': 'Missing data'}), 400

    business = Businesses.query.filter_by(Business_id=data['business_id']).first()
    if not business:
        return jsonify({'message': 'Business not found'}), 404

    email = current_user.Owner_email
    amount = int(data['total_amount'] * 100)  # Paystack expects the amount in kobo

    # Initialize Paystack transaction
    response = Transaction.initialize(reference=binascii.hexlify(os.urandom(12)).decode(), amount=amount, email=email)

    if response['status']:
        # Payment URL
        payment_url = response['data']['authorization_url']
        return jsonify({'payment_url': payment_url})

    return jsonify({'message': 'Payment initialization failed', 'error': response['message']}), 400

@app.route('/report', methods=['GET'])
@token_required
def report(user):
    business_id = request.args.get('business_id')
    business = Businesses.query.filter_by(Business_id=business_id).first()
    if not business:
        return jsonify({'message': 'Business not found'}), 404
    reports = BusinessReport.query.filter_by(business_id=business_id).all()
    report_data = []
    for report in reports:
        report_data.append({
            'report_id': report.report_id,
            'report_date': report.report_date,
            'total_sale': report.total_sales,
            'total_profit': report.total_profit
        })
    return jsonify(report_data)

@app.route('/verify_payment', methods=['GET'])
def verify_payment():
    reference = request.args.get('reference')
    if not reference:
        return jsonify({'message': 'Missing payment reference'}), 400

    # Verify transaction
    response = Transaction.verify(reference)

    if response['status']:
        # Payment was successful
        transaction_data = response['data']

        # Process the sale
        business_id = transaction_data['metadata']['business_id']
        staff_id = transaction_data['metadata']['staff_id']
        total_amount = transaction_data['amount'] / 100  # Convert from kobo to naira
        payment_method = 'Paystack'

        business = Businesses.query.filter_by(Business_id=business_id).first()
        if not business:
            return jsonify({'message': 'Business not found'}), 404

        staff = Staff.query.filter_by(Staff_id=staff_id).first()
        if not staff:
            return jsonify({'message': 'Staff not found'}), 404

        new_sale = Sale(business_id=business_id, staff_id=staff_id, total_amount=total_amount, payment_method=payment_method)
        db.session.add(new_sale)
        db.session.commit()

        for item in transaction_data['metadata']['items']:
            sale_item = SaleItem(sale_id=new_sale.Sale_id, inventory_id=item['inventory_id'], quantity=item['quantity'], price=item['price'])
            db.session.add(sale_item)

            inventory_item = Inventory.query.filter_by(Inventory_id=item['inventory_id']).first()
            if inventory_item:
                inventory_item.quantity -= item['quantity']
            else:
                return jsonify({'message': f'Item with ID {item["inventory_id"]} not found'}), 404

        db.session.commit()
        return jsonify({'message': 'Payment verified and processed successfully'})

    return jsonify({'message': 'Payment verification failed', 'error': response['message']}), 400

# Sample route
@app.route('/')
def home():
    return "Welcome to the Shop API Chommie!"

if __name__ == '__main__':
    app.run(debug=True)
    csrf.init_app(app)