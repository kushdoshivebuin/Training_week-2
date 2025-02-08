# Importing the required modules
from flask import Flask, render_template, request, flash, redirect, url_for , session , make_response
import os
from werkzeug.security import generate_password_hash, check_password_hash
from configparser import ConfigParser
import zxcvbn
from werkzeug.utils import secure_filename

# Import db and models
from models import db, Users, Contact , Tasks

# Create an instance of the Flask class
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png' , 'jpg' , 'jpeg' , 'gif' , 'pdf' , 'xlsx' , 'txt'}
UPLOAD_FOLDER = 'directory to upload the files'

# Reading the credentials from database.ini file
def connection_credentials(filename="file path where database.ini file is located", section="postgresqlcred"):
    """
    Reads the database credentials from a configuration file.
    
    Args:
        filename (str): Path to the configuration file.
        section (str): Section name containing database credentials.
        
    Returns:
        dict: Database credentials (user, password, host, database).
        
    Raises:
        Exception: If the specified section is not found in the configuration file.
    """
    parser = ConfigParser()
    parser.read(filename)

    dbcred = {}

    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            dbcred[param[0]] = param[1]
    else:
        raise Exception("Section {0} is not found in the {1} file")
    
    return dbcred

# Retrieve database credentials
database_cred = connection_credentials()

# Creating SQLALCHEMY Database URI
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{database_cred["user"]}:{database_cred["password"]}@{database_cred["host"]}/{database_cred["database"]}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the db with the app
db.init_app(app)

# Routes and Views

@app.route("/")
def home_page():
    """Render the home page."""
    return render_template('home.html')

@app.route("/login", methods=['GET', 'POST'])
def login_page():
    """
    Handles the login page where users enter their username and password.
    
    If login is successful, redirects to the dashboard page.
    If login fails, displays an error message.
    """
    if request.method == 'POST':
        # Getting the username and password from the form
        username = request.form['username']
        passw = request.form['password']

        # Checking if the user exists or not
        database_user = Users.query.filter_by(username=username).first()

        if database_user:
            if check_password_hash(database_user.password, passw):
                session['username'] = username
                return redirect(url_for('dashboard_page', username=username))
            else:
                flash("Incorrect password, please try again.", 'danger')
        else:
            flash("No user found with that username.", 'danger')
    
    # Prevent caching of the login page
    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

def categorize_password(password):
    """
    Categorizes password strength based on zxcvbn score.
    
    Args:
        password (str): The password to check.

    Returns:
        str: The strength category ("Easy", "Medium", "Hard").
    """
    result = zxcvbn.zxcvbn(password)

    # Score is between 0 (weak) and 4 (strong)
    score = result['score']
    
    # Classify password strength based on score
    if score == 0 or score == 1:
        return "Easy"
    elif score == 2:
        return "Medium"
    elif score == 3 or score == 4:
        return "Hard"

@app.route("/signup", methods=['GET', 'POST'])
def signup_page():
    """
    Handles the signup page where users can create a new account.
    
    Checks if email or username already exists and validates password strength.
    If successful, redirects to login page.
    """
    if request.method == 'POST':
        # Getting the email, username, password and confirm password from the signup page form
        email_address = request.form['email']
        username = request.form['username']
        passw = request.form['password']
        conf_passw = request.form['confirm_password']

        # Checking if the email address already exists or username has already been taken
        user_with_email = Users.query.filter_by(email=email_address).first()
        user_with_username = Users.query.filter_by(username=username).first()

        if user_with_email:
            flash("This email is already registered.", 'danger')
            return redirect(url_for('signup_page'))

        if user_with_username:
            flash("This username is already taken.", 'danger')
            return redirect(url_for('signup_page'))
        
        # Checking if password and confirm password are equal or not
        if passw != conf_passw:
            flash("Passwords do not match!", 'danger')
            return redirect(url_for('signup_page'))
        
        # Defining password strengths
        strength = categorize_password(passw)

        if strength == "Easy":
            flash("Your password is too weak! Please choose a stronger password.", 'danger')
            return redirect(url_for('signup_page'))  # Return to signup if password is weak
        
        hashed_password = generate_password_hash(passw, method="pbkdf2:sha256")
        new_user = Users(email=email_address, username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login_page'))

    return render_template('signup.html')

@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard_page():
    """
    Displays the dashboard page with tasks summary for the logged-in user.
    """
    if 'username' not in session:  # Check if user is logged in
        flash("You must be logged in to access the dashboard.", 'warning')
        return redirect(url_for('login_page'))  # Redirect to login if not logged in
    
    username = session['username']  # Get the username from the session

    # Fetch tasks for the logged-in user
    total_tasks = Tasks.query.filter_by(username=username , is_deleted = 'False').count()
    Completed_tasks = Tasks.query.filter_by(username=username, task_status='Completed' , is_deleted = 'False').count()
    Pending_tasks = Tasks.query.filter_by(username=username, task_status='Pending' , is_deleted = 'False').count()

    # Prevent caching of the dashboard page
    response = make_response(render_template('dashboard.html', 
                                             username=username,
                                             total_tasks=total_tasks,
                                             Completed_tasks=Completed_tasks,
                                             Pending_tasks=Pending_tasks))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

@app.route("/reset_password_request" , methods=['GET' , 'POST'])
def reset_password_request_page():
    """
    Handles the password reset request page where users can enter their email to receive a reset link.
    """
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if the email exists in the database
        user = Users.query.filter_by(email_address=email).first()

        if user:
            flash("Please enter your new password.", "info")
            return redirect(url_for('reset_password'))
        else:
            flash("No account found with that email address.", 'danger')
    
    # Prevent caching of the login page
    response = make_response(render_template('reset_password_request.html'))
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

@app.route("/reset_password/", methods=['GET', 'POST'])
def reset_password():
    """
    Allows users to reset their password after verifying their email address.
    """
    user = Users.query.filter_by().first()
    
    if not user:
        flash("No account found with that email address.", 'danger')
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.", 'danger')
            return redirect(url_for('reset_password'))
        
        # Defining password strengths
        strength = categorize_password(new_password)

        if strength == "Easy":
            flash("Your password is too weak! Please choose a stronger password.", 'danger')
            return redirect(url_for('reset_password'))  # Return to reset password if password is weak

        # Hash the new password and update it
        user.password = generate_password_hash(new_password , method="pbkdf2:sha256")
        db.session.commit()

        flash("Your password has been updated successfully!", 'success')
        return redirect(url_for('login_page'))
    
    # Prevent caching of the login page
    response = make_response(render_template('reset_password.html'))
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


@app.route("/about")
def about_us_page():
    """Render the about page."""
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """
    Handles the contact form where users can send a message.
    """
    if request.method == 'POST':
        # Getting the name, email, and message from the contact form
        name = request.form['name']
        email = request.form['email']
        mess = request.form['message']
        
        new_entry = Contact(full_name=name, email_address=email, message=mess)
        
        db.session.add(new_entry)
        db.session.commit()

        flash("Your message has been sent successfully!", "success")

    return render_template('contact.html')

@app.route("/logout")
def logout_page():
    """
    Logs the user out and redirects them to the home page.
    """
    session.pop('username', None)
    return redirect(url_for('home_page'))

@app.route('/tasks')
def task_list():
    """
    Displays the task list for the logged-in user.
    """
    if 'username' not in session:  # Check if user is logged in
        flash("You must be logged in to view tasks.", 'warning')
        return redirect(url_for('login_page'))  # Redirect to login if not logged in
    
    username = session['username']  # Get the username from the session
    status = request.args.get('status', 'All')  # Get status filter (default to 'All')

    # Fetch tasks based on the status filter and ensure is_deleted=False by default
    if status == 'All':
        tasks = Tasks.query.filter_by(username=username, is_deleted=False).order_by(Tasks.task_priority).all()
    else:
        tasks = Tasks.query.filter_by(username=username, task_status=status, is_deleted=False).order_by(Tasks.task_priority).all()

    # Prevent caching of the task list page
    response = make_response(render_template('task_list.html', tasks=tasks, status=status))
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

# Function to check if the file extension is allowed
def allowed_file(filename):
    """
    Checks if the uploaded file has an allowed extension.
    
    Args:
        filename (str): The name of the file to check.
        
    Returns:
        bool: True if the file extension is allowed, otherwise False.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/create_task', methods=['GET', 'POST'])
def create_task():
    """
    Allows the logged-in user to create a new task with optional file upload.
    """
    if request.method == 'POST':
        # Get form data
        task_title = request.form['task_title']
        task_description = request.form['task_description']
        task_priority = request.form['task_priority']
        task_status = request.form['task_status']
        
        username = session['username']  # Get the logged-in user's username from session

        file = request.files.get('file_upload')
        filename = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)

            file_url = url_for('static', filename='uploads/' + filename)

        else:
            file_url = None

        # Get the username from the session (no need for form data)
        if 'username' not in session:
            flash("You must be logged in to create a task.", 'warning')
            return redirect(url_for('login_page'))  # Redirect to login if not logged in

        # Create a new task object
        new_task = Tasks(
            task_title=task_title,
            task_description=task_description,
            task_priority=int(task_priority),  # Convert priority to integer
            task_status=task_status,
            username=username,  # Associate the task with the logged-in user
            task_file=file_url
        )

        # Add to database and commit
        db.session.add(new_task)
        db.session.commit()

        return redirect(url_for('dashboard_page'))  # Redirect to dashboard after creating the task

    return redirect(url_for('dashboard_page'))

@app.route('/toggle_task_status/<int:task_id>', methods=['POST'])
def toggle_task_status(task_id):
    """
    Toggles the task status between 'Pending' and 'Completed'.
    """
    if 'username' not in session:
        flash("You must be logged in to change task status.", 'warning')
        return redirect(url_for('login_page'))
    
    task = Tasks.query.filter_by(sr_no=task_id).first()

    if not task:
        flash("Task not found.", 'danger')
        return redirect(url_for('task_list'))

    # Toggle task status
    if task.task_status == 'Pending':
        task.task_status = 'Completed'
    else:
        task.task_status = 'Pending'

    db.session.commit()
    
    response = make_response(redirect(url_for('task_list')))
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response

@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    """
    Marks a task as deleted (sets 'is_deleted' flag to True).
    """
    task = Tasks.query.get_or_404(task_id)

    try:
        task.is_deleted = True
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash("Error marking task as deleted", "danger")

    return redirect(url_for('task_list', status='All'))

@app.errorhandler(404)
def page_not_found(e):
    """
    Handles 404 errors (page not found).
    """
    return render_template('404.html', message="The page you are looking for does not exist"), 404

# Running the app
if __name__ == "__main__":
    app.run(debug=True)
