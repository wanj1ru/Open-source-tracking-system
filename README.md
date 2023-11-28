# Open-source-tracking-system
# Flask Project README

This Flask project is a web application that provides functionality for user registration, login, file uploading, and URL scanning using the VirusTotal API.


## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/OmoshB/Flask.git
    cd Flask/
    ```

    This will clone the repository and change your current working directory to the project folder.

2. Set up a virtual environment (optional but recommended):

    ```bash
    # Create a virtual environment
    python -m venv venv

    # Activate the virtual environment
    # For Windows:
    source venv/Scripts/activate
    # For macOS/Linux:
    source venv/bin/activate
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

    This command installs all necessary Python packages listed in the `requirements.txt` file.

4. **Initialize the SQLite database:**

    Before running the Flask application, you need to initialize the SQLite database. Follow these steps:

    - Ensure you're in the project directory.
    - Run the following commands in your terminal or command prompt:

    ```bash
    flask db init
    flask db migrate -m "Initial database setup"
    flask db upgrade
    ```

    These commands initialize the migrations directory, create an initial migration, and apply the migration to create the database schema.

## Configuration

1. Set up environment variables:

    Create a `.env` file in the root directory and add the following:

    ```plaintext
    # .env file contents
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db'
    SECRET_KEY='your_secret_key_here'
    UPLOAD_FOLDER='static/files'
    MAIL_SERVER='smtp.gmail.com'
    MAIL_PORT=465
    MAIL_USERNAME='your_email@gmail.com'
    MAIL_PASSWORD='your_email_password'
    MAIL_USE_TLS=False
    MAIL_USE_SSL=True
    VIRUS_TOTAL_API_KEY='your_virus_total_api_key'
    ```

    Replace `'your_secret_key_here'`, `'your_email@gmail.com'`, `'your_email_password'`, and `'your_virus_total_api_key'` with your actual values.

## Usage

1. Run the Flask application:

    ```bash
    python app.py
    ```

    The application will start running at `http://127.0.0.1:5000/` by default.

2. Access the application in your web browser using the provided URL.


Thank you for using this Flask project!


