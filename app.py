from flask import Flask, render_template, url_for, redirect, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pandas as pd

# Flask miscellaneous
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'ctrlhackdel'

# Load the calorie data once when the server starts
calorie_data = pd.read_csv('calories.csv')
calorie_data['Cals_per100grams'] = calorie_data['Cals_per100grams'].str.replace(' cal', '').astype(int)

login_manager = LoginManager()  # class that handles log-in authentication
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # obtains a user based on their user id from the database

"""User Class"""

# Create a user class that stores the username and password and creates a unique id
class User(db.Model, UserMixin):
    """Manages the user's unique id and password"""
    id = db.Column(db.Integer, primary_key=True)  # specifications of a user's ID within the databse
    username = db.Column(db.String(20), nullable=False, unique=True)  # specifications of a user's name within the databse
    password = db.Column(db.String(80), nullable=False)  # specifications of a user's password within the databse

    def __init__(self, username, password):
        """Instance variables for username and password"""
        self.username = username
        self.password = password

    @staticmethod
    def search_user(query):
        """Finds user based on your query"""
        # Implement a search functionality based on the query
        return User.query.filter(User.username.ilike(f'%{query}%')).all()
    
    def __str__(self):
        """Returns the user's id and name"""
        return f"User ID: {self.id}, Username: {self.username}"

    def __eq__(self, other):
        """Compares 2 users' IDs"""
        if isinstance(other, User):
            return self.id == other.id and self.username == other.username
        return False
    

"""Form Classes"""


# Create the validation for the registration form
class RegisterForm(FlaskForm):
    """This class manages the specifications and restrictions for registration of a user"""
    def __init__(self):
        """Inherites user detials from User class"""
        super().__init__()

    # Creates a string field for the usename, with max and minimum length
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    # Creates a string field for the password, with max and minimum length
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")  # creates a submit field to sumbit username and password

    def validate_username(self, username):
        """Checks if a user already exists"""
        existing_user_username = User.query.filter_by(username=username.data).first()  # check if the username already exists in the database
        
        # If there an existing user, deny the creation of the account.
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    """Creates a form for the login of a user"""

    # Creates a string field for the username
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    # Creates a password field for the password
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")  # sumbit field to submit username and password


class WelcomePage:
    def __init__(self):
        pass

class HomepageRoute:
    """Routes and processes form data for the homepage."""

    @classmethod
    def process_form(cls, form):
        """Process form data when submitted."""
        if form.validate_on_submit():
            pass

    @classmethod
    def render_template(cls, form):
        """Render the homepage template."""
        return render_template('homepage.html', form=form, variable=session.get('output', ''))
    

@app.route('/')
def home():
    """Redirects the user to the homepage"""
    return redirect(url_for('homepage'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Create an instance of the LoginForm
    form = LoginForm()

    # Check if the form is submitted and valid
    if form.validate_on_submit():
        # Query the database for a user with the provided username
        user = User.query.filter_by(username=form.username.data).first()

        # If a user is found, check the password
        if user:
            # Check if the hashed password matches the input password
            if bcrypt.check_password_hash(user.password, form.password.data):
                # Log in the user and redirect to the homepage
                login_user(user)
                return redirect(url_for('homepage'))

    # Render the login template with the form (initial or after unsuccessful login)
    return render_template('login.html', form=form)


@app.route('/homepage', methods=['GET', 'POST'])
@login_required
def homepage():
    # Create an instance of the PromptForm
    form = WelcomePage()

    # Process the prompt from the user
    HomepageRoute.process_form(form)
    return HomepageRoute.render_template(form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    # Clear the ToDo list before logging out
    session.pop('todos', None)
    
    # Log the user out of thier session
    logout_user()

    # Redirect the user back to the login page
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Create an instance of the RegisterForm
    form = RegisterForm()

    # Check if the form is submitted and valid
    if form.validate_on_submit():
        # Generate a hashed password using bcrypt
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Create a new user with the provided username and hashed password
        new_user = User(username=form.username.data, password=hashed_password)

        # Add the new user to the database and commit changes
        db.session.add(new_user)
        db.session.commit()

        # Redirect to the login page after successful registration
        return redirect(url_for('login'))

    # Render the registration template with the form (initial or after unsuccessful registration)
    return render_template('register.html', form=form)


@app.route('/calorie-counter', methods=['GET', 'POST'])
def calorie():
    query = request.args.get('query', '')  # Get the search query
    search_results = []

    if query:
        # Filter items based on search query (case-insensitive)
        search_results = calorie_data[calorie_data['FoodItem'].str.contains(query, case=False)]
        search_results = search_results[['FoodItem', 'Cals_per100grams']].to_dict(orient='records')

    return render_template('calorie-calculator.html', search_results=search_results)

@app.route('/add_item', methods=['POST'])
def add_item():
    food_item = request.json.get('food_item')
    calories = request.json.get('calories')
    if 'selected_items' not in session:
        session['selected_items'] = []
    session['selected_items'].append({'food_item': food_item, 'calories': calories})
    session.modified = True
    return jsonify(session['selected_items'])

@app.route('/calculate_total', methods=['POST'])
def calculate_total():
    selected_items = session.get('selected_items', [])
    total_calories = sum(int(item['calories']) for item in selected_items)
    return jsonify(total_calories=total_calories)

if __name__ == '__main__':
    app.run(debug=True)