from flask import Flask, render_template, url_for, redirect, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from openai import OpenAI

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
