from datetime import datetime, date
from flask import current_app
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from sqlalchemy import event, select, func, case
from sqlalchemy.ext.hybrid import hybrid_property
from app import db, login_manager

# ======================
# USER MODELS 
# ======================
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    qualification = db.Column(db.String(120))
    dob = db.Column(db.String(10))  # YYYY-MM-DD
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    scores = db.relationship('Score', backref='user', lazy=True, cascade='all, delete-orphan')
    score_answers = db.relationship('ScoreAnswer', backref='user', lazy=True, cascade='all, delete-orphan')
    activities = db.relationship('Activity', backref='user', lazy=True)

    def set_password(self, password):
        """Improved password hashing with work factor"""
        self.password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16,
            iterations=100000  # Increased from default for better security
        )

    def check_password(self, password):
        """More secure password verification"""
        return check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        """Secure token generation with app context"""
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        """Token verification with proper error handling"""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt='password-reset-salt', max_age=expires_sec)['user_id']
            return User.query.get(user_id)
        except:
            return None

    def get_progress_stats(self):
        """New method from friend's project - calculates user progress"""
        return {
            'quizzes_taken': len(self.scores),
            'average_score': self.average_score(),
            'last_attempt': max(score.time_stamp_of_attempt for score in self.scores) if self.scores else None
        }

    def average_score(self):
        """Improved average calculation with null checks"""
        if not self.scores:
            return 0
        return sum(score.percentage for score in self.scores) / len(self.scores)

    def __repr__(self):
        return f'<User {self.username}>'

class Activity(db.Model):
    __tablename__ = 'activities'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(200))
    details = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Activity {self.action} by User {self.user_id}>'

# ======================
# QUIZ MODELS
# ======================
class Subject(db.Model):
    __tablename__ = 'subjects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    chapters = db.relationship('Chapter', backref='subject', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"Subject('{self.name}')"

class Chapter(db.Model):
    __tablename__ = 'chapters'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    quizzes = db.relationship('Quiz', backref='chapter', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"Chapter('{self.name}')"

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapters.id'), nullable=False)
    date_of_quiz = db.Column(db.Date)
    time_duration = db.Column(db.String(5))  # HH:MM
    remarks = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    questions = db.relationship('Question', back_populates='quiz', lazy=True, cascade='all, delete-orphan')
    scores = db.relationship('Score', backref='quiz', lazy=True, cascade='all, delete-orphan')

    @hybrid_property
    def questions_count(self):
        return len(self.questions)
        
    @questions_count.expression
    def questions_count(cls):
        return select(func.count(Question.id))\
               .where(Question.quiz_id == cls.id)\
               .scalar_subquery()

    def __repr__(self):
        return f"Quiz('{self.name}', '{self.date_of_quiz}')"

class Question(db.Model):
    __tablename__ = 'questions'
    
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_statement = db.Column(db.String(500), nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200))
    option4 = db.Column(db.String(200))
    correct_option = db.Column(db.String(1), nullable=False)  # '1', '2', '3', or '4'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    quiz = db.relationship('Quiz', back_populates='questions')
    score_answers = db.relationship('ScoreAnswer', backref='question', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"Question('{self.question_statement[:50]}...')"

class Score(db.Model):
    __tablename__ = 'scores'
    
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_scored = db.Column(db.Integer, nullable=False)
    time_stamp_of_attempt = db.Column(db.DateTime, default=datetime.utcnow)
    attempt_date = db.Column(db.DateTime, default=datetime.utcnow)
    time_taken = db.Column(db.Integer)  # In seconds
    details = db.Column(db.JSON)  # Stores full answer details
    answers = db.relationship('ScoreAnswer', backref='score', lazy=True, cascade='all, delete-orphan')

    @hybrid_property
    def percentage(self):
        """Calculate percentage based on total_scored and quiz questions_count"""
        quiz = db.session.get(Quiz, self.quiz_id)
        if not quiz or not quiz.questions_count:
            return 0
        return round((self.total_scored / quiz.questions_count) * 100, 2)

    @percentage.expression
    def percentage(cls):
        """SQL expression for percentage calculation"""
        return (func.cast(cls.total_scored, db.Float) / 
               (select(func.count(Question.id))
                .where(Question.quiz_id == cls.quiz_id)
                .scalar_subquery())) * 100

    def get_quiz_details(self):
        """Added method from friend's project for detailed results"""
        return {
            'quiz_name': self.quiz.name,
            'chapter': self.quiz.chapter.name,
            'subject': self.quiz.chapter.subject.name,
            'percentage': self.percentage,
            'timestamp': self.time_stamp_of_attempt
        }

    def __repr__(self):
        return f"Score(User {self.user_id}, Quiz {self.quiz_id}: {self.total_scored})"

class ScoreAnswer(db.Model):
    __tablename__ = 'score_answers'
    
    id = db.Column(db.Integer, primary_key=True)
    score_id = db.Column(db.Integer, db.ForeignKey('scores.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    answer = db.Column(db.String(1), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    time_taken = db.Column(db.Integer)  # In seconds
    answered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"ScoreAnswer(Question {self.question_id}, Correct: {self.is_correct})"

# ======================
# AUTHENTICATION SETUP
# ======================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@event.listens_for(User, 'before_update')
def update_last_login(mapper, connection, target):
    if 'last_login' in target.__dict__:
        target.last_login = datetime.utcnow()