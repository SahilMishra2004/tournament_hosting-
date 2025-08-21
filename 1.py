from app import app, db
with app.app_context():
    db.drop_all()  # Drops all tables (if they exist)
    db.create_all()  # Creates all tables with current schema