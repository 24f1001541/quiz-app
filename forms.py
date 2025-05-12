from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField,
    SelectField, TextAreaField, DateField,
    RadioField, HiddenField
)
from wtforms.validators import DataRequired, Length, EqualTo, Email
from wtforms.widgets import ListWidget, CheckboxInput

class BaseForm(FlaskForm):
    class Meta:
        csrf = False  # Disable CSRF for all forms

# Admin Forms
class AdminLoginForm(BaseForm):
    username = StringField('Username', 
                         validators=[DataRequired()])
    password = PasswordField('Password', 
                           validators=[DataRequired()])
    submit = SubmitField('Login')

class SubjectForm(BaseForm):
    name = StringField('Subject Name', 
                      validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', 
                              validators=[Length(max=200)])
    submit = SubmitField('Save')

class ChapterForm(BaseForm):
    name = StringField('Chapter Name', 
                      validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', 
                              validators=[Length(max=200)])
    subject_id = SelectField('Subject', 
                           coerce=int,
                           validators=[DataRequired()])
    submit = SubmitField('Save')

class QuizForm(BaseForm):
    name = StringField('Quiz Name', 
                      validators=[DataRequired(), Length(max=120)])
    date_of_quiz = DateField('Quiz Date', 
                            format='%Y-%m-%d',
                            validators=[DataRequired()])
    time_duration = StringField('Duration (HH:MM)', 
                              validators=[DataRequired()])
    remarks = TextAreaField('Remarks', 
                          validators=[Length(max=200)])
    chapter_id = SelectField('Chapter', 
                           coerce=int,
                           validators=[DataRequired()])
    submit = SubmitField('Save')

class QuestionForm(BaseForm):
    question_statement = TextAreaField('Question', 
                                     validators=[DataRequired(), Length(max=500)])
    option1 = StringField('Option 1', 
                         validators=[DataRequired(), Length(max=200)])
    option2 = StringField('Option 2', 
                         validators=[DataRequired(), Length(max=200)])
    option3 = StringField('Option 3', 
                         validators=[Length(max=200)])
    option4 = StringField('Option 4', 
                         validators=[Length(max=200)])
    correct_option = SelectField('Correct Answer', 
                               choices=[
                                   ('1', 'Option 1'),
                                   ('2', 'Option 2'),
                                   ('3', 'Option 3'),
                                   ('4', 'Option 4')
                               ],
                               validators=[DataRequired()])
    submit = SubmitField('Save')

# User Forms
class UserRegistrationForm(BaseForm):
    username = StringField('Username', 
                          validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', 
                           validators=[DataRequired()])
    full_name = StringField('Full Name', 
                           validators=[DataRequired(), Length(max=120)])
    qualification = StringField('Qualification', 
                              validators=[Length(max=120)])
    dob = DateField('Date of Birth', 
                   format='%Y-%m-%d',
                   validators=[DataRequired()])
    submit = SubmitField('Register')

class UserLoginForm(BaseForm):
    username = StringField('Username', 
                          validators=[DataRequired()])
    password = PasswordField('Password', 
                           validators=[DataRequired()])
    submit = SubmitField('Login')

# Password Reset Forms
class PasswordResetRequestForm(BaseForm):
    email = StringField('Email', 
                       validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class PasswordResetForm(BaseForm):
    password = PasswordField('New Password', 
                           validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password',
                                   validators=[DataRequired(), 
                                              EqualTo('password')])
    submit = SubmitField('Reset Password')

# Quiz Attempt Form
class QuizAttemptForm(BaseForm):
    """
    Base form for quiz attempts that will be dynamically extended
    with question fields in the route.
    Contains just the submit button by default.
    """
    submit = SubmitField('Submit Quiz',
                       render_kw={"class": "btn btn-primary"})
