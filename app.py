# Import necessary libraries and module
import os

import requests
from flask import Flask, render_template, url_for, redirect, request
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import InputRequired, Length, ValidationError, URL



# Initialize Flask application
app = Flask(__name__)

# Configure Flask app settings
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'

# Initialize Flask extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Flask-Mail configuration for email functionality
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'abc@email.com' #Replace abc@email.com with your email address 
app.config['MAIL_PASSWORD'] = 'emailpassword' #Replace emailpassword with your email password 
"""Do not forget to turn off less scure app access"""
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# API key for VirusTotal
VIRUS_TOTAL_API_KEY = '8ddf4f6ed069c4a5af3405bb627fdf37435fa3833a12f40f58763ff891f665ae'


# Define User class for SQLAlchemy model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False) 
    last_name = db.Column(db.String(100), nullable=False) 
    email_address = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# FlaskForm for user registration
class RegistrationForm(FlaskForm):
    first_name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "First Name"})
    last_name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Last Name"})
    email_address = StringField(validators=[InputRequired(), Length(max=30)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit= SubmitField("Register")

    def validate_email_address(self, email_address):
        existing_email_address= User.query.filter_by(
            email_address=email_address.data).first()
        
        if existing_email_address:
            raise ValidationError(
                "That email address is already in use. Please choose a different one")
            
        
# FlaskForm for user login
class LoginForm(FlaskForm):
    email_address = StringField(validators=[InputRequired(), Length(max=30)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit= SubmitField("Login")


# FlaskForm for file upload
class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[InputRequired()]) 
    submit = SubmitField('Upload File')


# FlaskForm for URL scanning
class URLScanForm(FlaskForm):
    url = StringField('URL', validators=[InputRequired(), URL(message="Invalid URL")])
    submit = SubmitField('Scan URL')


# Route for the home page
@app.route('/', methods=['GET', 'POST'])
def home():
  message_sent=False

  if request.method == 'POST':
      # Process contact form submission
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # Send email
        msg = Message("New Contact Form Submission", 
                      sender='abc@email.com',  # Replace with your email address
                      recipients=['abc@email.com'])  # Replace with your email address
        msg.body = render_template('email_template.txt', 
                                   full_name=full_name, 
                                   email=email, 
                                   subject=subject, 
                                   message=message)
        mail.send(msg)

        message_sent = True 

  return render_template('home.html', message_sent=message_sent)


# Route for the dashboard page (requires login)
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UploadFileForm()
    scan_result = None

    if form.validate_on_submit():
        # Process file upload and scan
        file = form.file.data
        file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)

        # Call function to scan the uploaded file
        scan_result = scan_file(file_path)
       
        

    user = current_user
    return render_template('dashboard.html', user=user, form=form, scan_result=scan_result)

# Function to scan a file using VirusTotal API
def scan_file(file_path):
    # VirusTotal API endpoint for file scanning
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUS_TOTAL_API_KEY}
    files = {'file': open(file_path, 'rb')}

    try:
        # Submit the file for scanning
        response = requests.post(url, files=files, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors (4XX or 5XX)

        # Get the scan report after submitting the file
        scan_id = response.json().get('scan_id')
        if scan_id:
       

            report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
            report_params = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': scan_id}

            # Retrieve scan results
            report_response = requests.get(report_url, params=report_params)
            report_response.raise_for_status()

            result = report_response.json()  # Parse JSON response
            scan_results = {vendor: details['result'] for vendor, details in result['scans'].items()}
            return scan_results
        
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return {'error': 'Request failed'}

    except ValueError as ve:
        print(f"JSON decoding error: {ve}")
        return {'error': 'JSON decoding failed'}

    except Exception as ex:
        print(f"Unexpected error: {ex}")
        return {'error': 'An unexpected error occurred'}

    return {'error': 'No scan results found'}


@app.route('/scan_url', methods=['GET', 'POST'])
@login_required
def scan_url():
    form = URLScanForm()

    if form.validate_on_submit():
        url_to_scan = form.url.data

        # Call function to scan the URL
        scan_result = scan_url(url_to_scan)

        user = current_user
        return render_template('scan_url.html', user=user, form=form, scan_result=scan_result)

    user = current_user
    return render_template('scan_url.html', user=user, form=form)

def scan_url(url):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': VIRUS_TOTAL_API_KEY, 'url': url}

    try:
        response = requests.post(url, data=params)
        response.raise_for_status()  # Raise an exception for HTTP errors (4XX or 5XX)

        # Get the scan report after submitting the URL
        scan_id = response.json().get('scan_id')
        if scan_id:
         

            report_url = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={VIRUS_TOTAL_API_KEY}&resource={scan_id}'
            report_response = requests.get(report_url)
            report_response.raise_for_status()

            result = report_response.json()  # Parse JSON response
            scan_results = {vendor: details['result'] for vendor, details in result['scans'].items()}
            return scan_results

    except requests.RequestException as e:
        # Handle request exceptions here (e.g., connection errors, timeouts, etc.)
        print(f"Request error: {e}")
        return {'error': 'Request failed'}

    except ValueError as ve:
        # Handle JSON decoding errors
        print(f"JSON decoding error: {ve}")
        return {'error': 'JSON decoding failed'}

    except Exception as ex:
        # Handle any other unexpected exceptions
        print(f"Unexpected error: {ex}")
        return {'error': 'An unexpected error occurred'}

    return {'error': 'No scan results found'}

# Route for handling user login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for handling user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() 
    if  form.validate_on_submit():
        user = User.query.filter_by(email_address= form.email_address.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

# Route for user registration
@app.route('/logout',  methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    hashed_password = None

 

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
          # Create a new User object and add it to the database
        new_user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email_address=form.email_address.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login')) # Redirect to the login page after successful registration


    return render_template('register.html', form=form)

# Run the Flask app if this script is executed
if __name__ == "__main__":
    app.run(debug=True)

