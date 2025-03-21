"""
Entry point for the ccc_emergency_map application.

Creates the Flask app instance via create_app() and starts the server if run as student.
"""
from app.__init__ import create_app, db

app = create_app()

@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
    print("Database tables created")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9002, debug=app.config.get("DEBUG", False))
