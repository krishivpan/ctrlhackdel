from app import db, app

# Ensure the application context is active
with app.app_context():
    db.create_all()  # This will create the database file (database.db) and the necessary tables based on your model
    print("Database and tables created successfully!")
