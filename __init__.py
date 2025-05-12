from flask import Flask, render_template, make_response, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_moment import Moment
from datetime import datetime, timedelta
import os
import secrets
import logging
from logging.handlers import RotatingFileHandler

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
moment = Moment()

def create_app(config_class=None):
    """Enhanced application factory combining both versions"""
    app = Flask(__name__, instance_relative_config=True)
    
    # Configure application
    configure_app(app, config_class)
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Setup logging
    configure_logging(app)
    
    # Register components
    register_blueprints(app)
    register_context_processors(app)
    register_error_handlers(app)
    register_commands(app)
    register_health_check(app)
    
    # Database setup
    setup_database(app)
    
    return app

def configure_app(app, config_class=None):
    """Combined configuration with enhanced security"""
    if config_class:
        app.config.from_object(config_class)
    else:
        # Setup instance folder
        os.makedirs(app.instance_path, exist_ok=True)
        
        # Generate secure secret key
        secret_key_path = os.path.join(app.instance_path, 'secret_key')
        if not os.path.exists(secret_key_path):
            with open(secret_key_path, 'w') as f:
                f.write(secrets.token_hex(32))
        
        with open(secret_key_path) as f:
            secret_key = f.read().strip()
        
        # Base configuration
        app.config.from_mapping(
            # Core
            SECRET_KEY=os.environ.get('SECRET_KEY', secret_key),
            
            # Database (simplified from your friend's version)
            SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 
                'sqlite:///' + os.path.join(app.instance_path, 'quiz_master.db')),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            
            # Security (from your version)
            PERMANENT_SESSION_LIFETIME=timedelta(days=7),
            SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            WTF_CSRF_ENABLED=False,
        )

def initialize_extensions(app):
    """Initialize all Flask extensions"""
    # Database
    db.init_app(app)
    
    # Login Manager
    login_manager.init_app(app)
    login_manager.login_view = 'main.user_login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    
    # Moment.js for timestamps
    moment.init_app(app)
    
    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

def configure_logging(app):
    """Configure application logging"""
    if not app.debug and not app.testing:
        os.makedirs('logs', exist_ok=True)
        file_handler = RotatingFileHandler(
            'logs/quiz_master.log',
            maxBytes=10240,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Quiz Master startup')

def register_health_check(app):
    """Register health check endpoint"""
    @app.route('/health')
    def health_check():
        return make_response('OK', 200)

def create_initial_data():
    """Create initial database data"""
    from app.models import User  # Make sure to import your User model
    
    # Example: Create an admin user if none exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com')
        admin.set_password('admin123')  # Make sure your User model has this method
        db.session.add(admin)
        db.session.commit()

def register_blueprints(app):
    """Register Flask blueprints"""
    from app.routes import main
    app.register_blueprint(main)

def register_context_processors(app):
    """Register context processors"""
    @app.context_processor
    def inject_globals():
        return dict(
            app_name="Quiz Master",
            current_year=datetime.now().year,
            debug_mode=app.debug
        )

def register_error_handlers(app):
    """Register error handlers"""
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500

def register_commands(app):
    """Register custom CLI commands"""
    @app.cli.command('init-db')
    def initialize_database():
        """Initialize the database"""
        db.create_all()
        create_initial_data()
        app.logger.info("Database initialized")

def setup_database(app):
    """Initialize database"""
    with app.app_context():
        db.create_all()
        create_initial_data()

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
    