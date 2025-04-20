from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms import TextAreaField, SelectMultipleField, DateTimeField, IntegerField, RadioField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional, NumberRange

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=4, max=20, message="Username must be between 4 and 20 characters")
    ])
    
    email = StringField('Email', validators=[DataRequired()])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    
    password_confirm = PasswordField('Confirm Password', validators=[
        DataRequired(), 
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('Register')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), 
        EqualTo('new_password', message="Passwords must match")
    ])
    submit = SubmitField('Change Password')

class ManageAttributesForm(FlaskForm):
    """Form for managing user attributes."""
    attributes = SelectMultipleField('Attributes', coerce=int)
    submit = SubmitField('Update Attributes')

class FileUploadForm(FlaskForm):
    """Form for uploading files."""
    file = FileField('File', validators=[FileRequired()])
    name = StringField('Name (Optional)', validators=[Length(max=100)])
    description = TextAreaField('Description (Optional)', validators=[Length(max=500)])
    encrypt = BooleanField('Encrypt File', default=True)
    submit = SubmitField('Upload')

class ShareFileForm(FlaskForm):
    """Form for sharing a file with another user."""
    user_id = SelectField('Share with User', validators=[DataRequired()], coerce=int)
    permissions = SelectMultipleField('Permissions', choices=[
        ('read', 'Read'),
        ('write', 'Write'),
        ('delete', 'Delete')
    ], default=['read'])
    expiration = DateTimeField('Expiration (Optional)', validators=[Optional()])
    policy_id = SelectField('Apply Policy', validators=[Optional()], coerce=int)
    submit = SubmitField('Share File')

class RemoveShareForm(FlaskForm):
    """Form for removing shared access to a file."""
    submit = SubmitField('Remove')

class PolicyForm(FlaskForm):
    """Form for creating and editing policies."""
    name = StringField('Policy Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    priority = SelectField('Priority', 
                          choices=[(1, '1 - Low'), (2, '2 - Medium'), (3, '3 - High'), 
                                  (4, '4 - Critical'), (5, '5 - Highest')],
                          validators=[DataRequired()],
                          default=3,
                          coerce=int)
    is_active = BooleanField('Active', default=True)
    condition_type = RadioField('Condition Type', 
                              choices=[('OR', 'OR (Any selected attribute allows access)'), 
                                      ('AND', 'AND (All selected attributes are required)')],
                              default='OR')
    submit = SubmitField('Create Policy')

class AttributeForm(FlaskForm):
    """Form for creating attributes."""
    name = StringField('Attribute Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=255)])
    submit = SubmitField('Create Attribute')