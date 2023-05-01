import re
import requests
import bcrypt
import stripe
from bson.objectid import ObjectId
from datetime import datetime
from decimal import Decimal
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

app = Flask(__name__)

# Configuration settings
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/DonateALeg'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

# Stripe API configuration
stripe.api_key = "your_stripe_api_key"

# Initialize extensions
mongo = PyMongo(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = mongo.db.users.find_one({"username": username.data})
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = mongo.db.users.find_one({"email": email.data})
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class DonationForm(FlaskForm):
    amount = DecimalField('Amount', validators=[DataRequired()])
    currency = StringField('Currency', validators=[DataRequired()])
    cardholder_name = StringField('Cardholder Name', validators=[DataRequired()])
    card_number = StringField('Card Number', validators=[DataRequired()])
    expiry_date = StringField('Expiry Date (MM/YY)', validators=[DataRequired()])
    cvv = StringField('CVV', validators=[DataRequired()])
    submit = SubmitField('Donate')

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user)
    return None

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.email = user_data["email"]

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        mongo.db.users.insert_one({"username": form.username.data, "email": form.email.data, "password": hashed_password})
        flash('Your account has been created! You are now able to log in.', 'success')
        
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = mongo.db.users.find_one({"email": form.email.data})
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user["password"]):
            user_obj = User(user)
            login_user(user_obj)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/donate', methods=['GET', 'POST'])
def donate():
    form = DonationForm()
    if form.validate_on_submit():
        # Validate the form fields
        amount = form.amount.data
        currency = form.currency.data.upper()
        cardholder_name = form.cardholder_name.data
        card_number = form.card_number.data
        expiry_date = form.expiry_date.data
        cvv = form.cvv.data

        if not re.match(r'^[A-Za-z]+\s[A-Za-z]+$', cardholder_name):
            flash('Cardholder Name must consist of a first and last name', 'danger')
            return render_template('donate.html', title='Donate', form=form)

        if len(card_number) != 16 or not card_number.isdigit():
            flash('Card Number must be 16 digits', 'danger')
            return render_template('donate.html', title='Donate', form=form)

        if not re.match(r'^\d{2}\/\d{2}$', expiry_date):
            flash('Expiry Date must have proper month and year formatting (MM/YY)', 'danger')
            return render_template('donate.html', title='Donate', form=form)

        if len(cvv) != 3 or not cvv.isdigit():
            flash('CVV must be 3 numeric numbers', 'danger')
            return render_template('donate.html', title='Donate', form=form)

        # Fetch USD exchange rate
        response = requests.get(f'https://api.exchangerate-api.com/v4/latest/{currency}')
        if response.status_code != 200:
            flash('Error fetching exchange rate. Please try again later.', 'danger')
            return render_template('donate.html', title='Donate', form=form)

        exchange_rate = response.json().get('rates', {}).get('USD')
        if exchange_rate is None:
            flash('Unsupported currency. Please try again with a different currency.', 'danger')
            return render_template('donate.html', title='Donate', form=form)

        # Calculate amount in USD
        amount_in_usd = float(amount) * exchange_rate

        # Convert amount_in_usd to float before storing it in the database
        amount_in_usd_float = float(amount_in_usd)
        
        # Implement Stripe or PayPal processing here
        mongo.db.donations.insert_one({
            "amount": amount_in_usd_float,
            "currency": "USD",
            "payment_method": "Stripe",
            "payment_info": {"transaction_id": "example_transaction_id"},
            "timestamp": datetime.utcnow()
        })

        flash('Your donation of ${:.2f} has been processed. Thank you for your generosity!'.format(amount_in_usd), 'success')
        return redirect(url_for('donate'))
    return render_template('donate.html', title='Donate', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home')

if __name__ == '__main__':
    app.run(debug=True)


