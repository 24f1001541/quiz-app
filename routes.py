from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import current_user, login_user, login_required, logout_user
from sqlalchemy import func, case
from sqlalchemy.exc import SQLAlchemyError 
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import RadioField
from wtforms.validators import DataRequired
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64


from app import db, login_manager
from app.forms import (
    AdminLoginForm, SubjectForm, ChapterForm, 
    QuizForm, QuestionForm, UserRegistrationForm, 
    UserLoginForm, PasswordResetRequestForm, 
    PasswordResetForm, QuizAttemptForm
)
from app.models import User, Subject, Chapter, Quiz, Question, Score, ScoreAnswer, Activity
from app.utils.plotter import performance_plot, distribution_plot

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def home():
    try:
        return render_template('home.html')
    except Exception as e:
        current_app.logger.error(f"Error in home route: {str(e)}")
        raise

# ======================
# COMMON ROUTES
# ======================

@main.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.home'))

# ======================
# ADMIN ROUTES
# ======================

@main.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = User.query.filter_by(username=form.username.data, is_admin=True).first()
        if admin and admin.check_password(form.password.data):
            login_user(admin)
            session['admin_logged_in'] = True
            return redirect(url_for('main.admin_dashboard'))
        flash('Invalid admin credentials', 'error')
    return render_template('admin/login.html', form=form)

@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    stats = {
        'subjects': Subject.query.count(),
        'chapters': Chapter.query.count(),
        'quizzes': Quiz.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'recent_activities': Activity.query.order_by(Activity.timestamp.desc()).limit(5).all()
    }
    
    return render_template('admin/dashboard.html', **stats)

# Subject Management
@main.route('/admin/subjects')
@login_required
def admin_subjects():
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    return render_template('admin/subjects.html', subjects=Subject.query.all())

@main.route('/admin/subject/create', methods=['GET', 'POST'])
@login_required
def admin_create_subject():
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    form = SubjectForm()
    if form.validate_on_submit():
        subject = Subject(name=form.name.data, description=form.description.data)
        db.session.add(subject)
        db.session.commit()
        flash('Subject created successfully!', 'success')
        return redirect(url_for('main.admin_subjects'))
    return render_template('admin/create_subject.html', form=form)

@main.route('/admin/subject/edit/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_subject(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    subject = Subject.query.get_or_404(subject_id)
    form = SubjectForm(obj=subject)
    
    if form.validate_on_submit():
        form.populate_obj(subject)
        db.session.commit()
        flash('Subject updated successfully!', 'success')
        return redirect(url_for('main.admin_subjects'))
    return render_template('admin/edit_subject.html', form=form, subject=subject)

@main.route('/admin/subject/delete/<int:subject_id>', methods=['POST'])
@login_required
def admin_delete_subject(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted successfully!', 'success')
    return redirect(url_for('main.admin_subjects'))

# Chapter Management
@main.route('/admin/chapters/<int:subject_id>')
@login_required
def admin_chapters(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template('admin/chapters.html', subject=subject, chapters=chapters)

@main.route('/admin/chapter/create/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def admin_create_chapter(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    subject = Subject.query.get_or_404(subject_id)
    form = ChapterForm()
    
    if hasattr(form, 'subject_id'):
        form.subject_id.choices = [(s.id, s.name) for s in Subject.query.all()]
        form.subject_id.data = subject_id
    
    if form.validate_on_submit():
        chapter = Chapter(
            name=form.name.data,
            description=form.description.data,
            subject_id=subject_id
        )
        db.session.add(chapter)
        db.session.commit()
        flash('Chapter created successfully!', 'success')
        return redirect(url_for('main.admin_chapters', subject_id=subject.id))
    
    return render_template('admin/create_chapter.html', form=form, subject=subject)

@main.route('/admin/chapter/edit/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_chapter(chapter_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    chapter = Chapter.query.get_or_404(chapter_id)
    form = ChapterForm(obj=chapter)
    form.subject_id.choices = [(s.id, s.name) for s in Subject.query.all()]
    
    if form.validate_on_submit():
        form.populate_obj(chapter)
        db.session.commit()
        flash('Chapter updated successfully!', 'success')
        return redirect(url_for('main.admin_chapters', subject_id=chapter.subject_id))
    return render_template('admin/edit_chapter.html', form=form, chapter=chapter)

@main.route('/admin/chapter/delete/<int:chapter_id>', methods=['POST'])
@login_required
def admin_delete_chapter(chapter_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id
    db.session.delete(chapter)
    db.session.commit()
    flash('Chapter deleted successfully!', 'success')
    return redirect(url_for('main.admin_chapters', subject_id=subject_id))

# Quiz Management
@main.route('/admin/quizzes/<int:chapter_id>')
@login_required
def admin_quizzes(chapter_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return render_template('admin/quizzes.html', chapter=chapter, quizzes=quizzes)

@main.route('/admin/quiz/create/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
def admin_create_quiz(chapter_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    chapter = Chapter.query.get_or_404(chapter_id)
    form = QuizForm()
    form.chapter_id.choices = [(c.id, c.name) for c in Chapter.query.all()]
    form.chapter_id.data = chapter_id
    
    if form.validate_on_submit():
        quiz = Quiz(
            name=form.name.data,
            date_of_quiz=form.date_of_quiz.data,
            time_duration=form.time_duration.data,
            remarks=form.remarks.data,
            chapter_id=chapter_id
        )
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
        return redirect(url_for('main.admin_quizzes', chapter_id=chapter_id))
    
    return render_template('admin/create_quiz.html', form=form, chapter=chapter)

@main.route('/admin/quiz/edit/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_quiz(quiz_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuizForm(obj=quiz)
    form.chapter_id.choices = [(c.id, c.name) for c in Chapter.query.all()]
    
    if form.validate_on_submit():
        form.populate_obj(quiz)
        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('main.admin_quizzes', chapter_id=quiz.chapter_id))
    
    return render_template('admin/edit_quiz.html', form=form, quiz=quiz)

@main.route('/admin/quiz/delete/<int:quiz_id>', methods=['POST'])
@login_required
def admin_delete_quiz(quiz_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter_id = quiz.chapter_id
    Question.query.filter_by(quiz_id=quiz_id).delete()
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz and all its questions deleted successfully!', 'success')
    return redirect(url_for('main.admin_quizzes', chapter_id=chapter_id))

# Question Management
@main.route('/admin/questions/<int:quiz_id>')
@login_required
def admin_questions(quiz_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('admin/questions.html', quiz=quiz, questions=questions)

@main.route('/admin/question/create/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def admin_create_question(quiz_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuestionForm()
    
    if form.validate_on_submit():
        question = Question(
            question_statement=form.question_statement.data,
            option1=form.option1.data,
            option2=form.option2.data,
            option3=form.option3.data,
            option4=form.option4.data,
            correct_option=form.correct_option.data,
            quiz_id=quiz_id
        )
        db.session.add(question)
        db.session.commit()
        flash('Question created successfully!', 'success')
        return redirect(url_for('main.admin_questions', quiz_id=quiz_id))
    
    return render_template('admin/create_question.html', form=form, quiz=quiz)

@main.route('/admin/question/edit/<int:question_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_question(question_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    question = Question.query.get_or_404(question_id)
    quiz = Quiz.query.get_or_404(question.quiz_id)
    form = QuestionForm(obj=question)
    
    if form.validate_on_submit():
        form.populate_obj(question)
        db.session.commit()
        flash('Question updated successfully!', 'success')
        return redirect(url_for('main.admin_questions', quiz_id=question.quiz_id))
    
    return render_template('admin/edit_question.html', form=form, question=question, quiz=quiz)

@main.route('/admin/question/delete/<int:question_id>', methods=['POST'])
@login_required
def admin_delete_question(question_id):
    if not current_user.is_admin:
        return redirect(url_for('main.home'))
    
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('main.admin_questions', quiz_id=quiz_id))

@main.route('/admin/summary')
@login_required
def admin_summary():
    if not current_user.is_admin:
        flash('Administrator access required', 'error')
        return redirect(url_for('main.home'))

    # Get first chapter if exists
    first_chapter = Chapter.query.first()
    chapter_id = first_chapter.id if first_chapter else None

    empty_state_data = {
        'is_empty_state': True,
        'ranked_attempts': [{
            'rank': 1,
            'student': "No data available",
            'quiz': "No quizzes taken",
            'score': "0/0",
            'percentage': 0,
            'time_taken': 'N/A',
            'date': 'N/A'
        }],
        'question_analytics': [],
        'class_average': 0,
        'total_users': User.query.count(),
        'total_quizzes': Quiz.query.count(),
        'top_performers': [],
        'weakest_areas': [],
        'recent_attempts': [],
        'plot_image': None,
        'dist_plot': None,
        'chapter_id': chapter_id
    }

    try:
        # Check if there's any quiz data
        if not Score.query.first():
            flash('No quiz data available yet. Please create quizzes and have users attempt them.', 'info')
            return render_template('admin/summary.html', **empty_state_data)

        # Get all attempts with user and quiz info
        attempts_query = db.session.query(
            Score,
            User.full_name,
            Quiz.name,
            Quiz.questions_count
        ).join(
            User, User.id == Score.user_id
        ).join(
            Quiz, Quiz.id == Score.quiz_id
        ).order_by(
            Score.time_stamp_of_attempt.desc()
        ).all()

        if not attempts_query:
            return render_template('admin/summary.html', **empty_state_data)

        # Process attempts data
        ranked_attempts = []
        for idx, (score, full_name, quiz_name, questions_count) in enumerate(attempts_query, 1):
            percentage = round((score.total_scored / questions_count) * 100, 2) if questions_count else 0
            ranked_attempts.append({
                'rank': idx,
                'student': full_name or "Unknown",
                'quiz': quiz_name or "Unnamed Quiz",
                'score': f"{score.total_scored}/{questions_count}",
                'percentage': percentage,
                'time_taken': f"{score.time_taken}s" if score.time_taken else 'N/A',
                'date': score.time_stamp_of_attempt.strftime('%Y-%m-%d') if score.time_stamp_of_attempt else 'N/A'
            })

        # Get question analytics
        question_stats = db.session.query(
            Question.id,
            Question.question_statement,
            func.sum(
                case(
                    (ScoreAnswer.answer == Question.correct_option, 1),
                    else_=0
                )
            ).label('correct_answers'),
            func.count(ScoreAnswer.id).label('total_attempts')
        ).outerjoin(
            ScoreAnswer, Question.id == ScoreAnswer.question_id
        ).group_by(
            Question.id, Question.question_statement
        ).all()

        question_analytics = []
        for q in question_stats:
            difficulty = round((q.correct_answers or 0)/(q.total_attempts or 1)*100) if q.total_attempts else 0
            question_analytics.append({
                'id': q.id,
                'question': (q.question_statement[:50] + '...') if q.question_statement else 'Unknown',
                'difficulty': f"{difficulty}%",
                'correct': q.correct_answers or 0,
                'attempts': q.total_attempts or 0
            })

        # Calculate class average
        total_percentage = sum(a['percentage'] for a in ranked_attempts)
        class_average = round(total_percentage / len(ranked_attempts), 2) if ranked_attempts else 0

        # Generate plots
        performance_data = [a['percentage'] for a in ranked_attempts[:5]] or [0]
        performance_labels = [a['student'] for a in ranked_attempts[:5]] or ["No data"]
        dist_data = [a['percentage'] for a in ranked_attempts] or [0]

        plot_image = performance_plot(performance_labels, performance_data)
        dist_plot = distribution_plot(dist_data)

        # Identify weakest areas (questions with lowest correct percentage)
        weakest_areas = sorted(
            [q for q in question_analytics if q['difficulty'].endswith('%')],
            key=lambda x: float(x['difficulty'][:-1])
        )[:5]

        return render_template('admin/summary.html',
            is_empty_state=False,
            ranked_attempts=ranked_attempts,
            question_analytics=question_analytics,
            class_average=class_average,
            total_users=User.query.count(),
            total_quizzes=Quiz.query.count(),
            top_performers=ranked_attempts[:5],
            weakest_areas=weakest_areas,
            recent_attempts=ranked_attempts[:10],
            plot_image=plot_image,
            dist_plot=dist_plot,
            chapter_id=chapter_id
        )

    except Exception as e:
        current_app.logger.error(f"Summary generation failed: {str(e)}", exc_info=True)
        flash(f'Error generating summary: {str(e)}', 'error')
        return render_template('admin/summary.html', **empty_state_data)

# ======================
# COMPLETE USER ROUTES
# ======================

# Registration
@main.route('/user/register', methods=['GET', 'POST'])
def user_register():
    form = UserRegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            full_name=form.full_name.data,
            qualification=form.qualification.data,
            dob=form.dob.data
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('main.user_login'))
    return render_template('user/register.html', form=form)

# Login
@main.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for('main.user_dashboard'))
    
    form = UserLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.user_dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('user/login.html', form=form)

# Dashboard
@main.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user/dashboard.html',
                         user=current_user,
                         quizzes=Quiz.query.all())

# Quiz Taking
@main.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == 'POST':
        
        score = sum(
            1 for q in quiz.questions 
            if request.form.get(f'question_{q.id}') == str(q.correct_option))
        
        # Create and commit the Score first
        new_score = Score(
            quiz_id=quiz_id,
            user_id=current_user.id,
            total_scored=score,
            time_stamp_of_attempt=datetime.utcnow()
        )
        db.session.add(new_score)
        db.session.commit()  # Commit to get the score_id
        
        # Now create ScoreAnswer records with the valid score_id
        for q in quiz.questions:
            answer = ScoreAnswer(
                score_id=new_score.id,  # Now has a valid ID
                question_id=q.id,
                user_id=current_user.id,
                answer=request.form.get(f'question_{q.id}'),
                is_correct=(request.form.get(f'question_{q.id}') == str(q.correct_option)),
                answered_at=datetime.utcnow()
            )
            db.session.add(answer)
        
        db.session.commit()  # Commit the answers
        
        flash(f'Quiz completed! Score: {score}/{len(quiz.questions)}', 'success')
        return redirect(url_for('main.scores'))
    
    return render_template('user/quiz.html', quiz=quiz)

# Scores Page (Detailed List)
@main.route('/scores')
@login_required
def scores():
    scores = db.session.query(
        Score,
        Quiz.name.label('quiz_name')
    ).join(Quiz).filter(
        Score.user_id == current_user.id
    ).order_by(
        Score.time_stamp_of_attempt.desc()
    ).all()
    
    return render_template('user/scores.html', scores=scores)

# Summary Page (With Graphs)
@main.route('/summary')
@login_required
def summary():
    # Get all scores for charts
    scores = Score.query.filter_by(
        user_id=current_user.id
    ).join(Quiz).order_by(
        Score.time_stamp_of_attempt
    ).all()
    
    # Prepare data for charts
    quiz_names = [score.quiz.name for score in scores]
    percentages = [score.percentage for score in scores]
    
    # Create performance trend chart
    plt.figure(figsize=(10,5))
    plt.plot(quiz_names, percentages, marker='o', color='#4CAF50')
    plt.title('Your Performance Trend')
    plt.xlabel('Quiz')
    plt.ylabel('Score (%)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    trend_img = io.BytesIO()
    plt.savefig(trend_img, format='png')
    trend_img.seek(0)
    trend_url = base64.b64encode(trend_img.getvalue()).decode()
    plt.close()
    
    # Create score distribution chart
    plt.figure(figsize=(10,5))
    plt.hist(percentages, bins=10, color='#2196F3')
    plt.title('Score Distribution')
    plt.xlabel('Score Range (%)')
    plt.ylabel('Number of Quizzes')
    
    dist_img = io.BytesIO()
    plt.savefig(dist_img, format='png')
    dist_img.seek(0)
    dist_url = base64.b64encode(dist_img.getvalue()).decode()
    plt.close()
    
    # Calculate statistics
    stats = {
        'total_quizzes': len(scores),
        'average_score': sum(percentages)/len(percentages) if scores else 0,
        'highest_score': max(percentages) if scores else 0,
        'lowest_score': min(percentages) if scores else 0
    }
    
    return render_template('user/summary.html',
                         trend_url=trend_url,
                         dist_url=dist_url,
                         stats=stats,
                         scores=scores)

# Quiz Review
@main.route('/quiz/<int:quiz_id>/review/<int:score_id>')
@login_required
def review_quiz(quiz_id, score_id):
    score = Score.query.filter_by(
        id=score_id,
        user_id=current_user.id
    ).first_or_404()
    
    answers = ScoreAnswer.query.filter_by(
        score_id=score_id
    ).all()
    
    return render_template('user/quiz_review.html',
                         quiz=score.quiz,
                         score=score,
                         answers=answers)

# Logout
@main.route('/user/logout')
@login_required
def user_logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.home'))