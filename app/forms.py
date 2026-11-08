"""WTForms definitions shared across blueprints."""

from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from sqlalchemy import func
from wtforms import (
    BooleanField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Regexp,
    ValidationError,
)

from app.models import PERMISSION_DOWNLOAD, PERMISSION_LABELS, PERMISSION_VIEW, User


def _strong_password(form, field):
    value = field.data or ""
    if not any(char.isalpha() for char in value):
        raise ValidationError("Password must contain at least one letter.")
    if not any(char.isdigit() for char in value):
        raise ValidationError("Password must contain at least one number.")


class RegistrationForm(FlaskForm):
    full_name = StringField(
        "Full name",
        validators=[DataRequired(), Length(min=2, max=120)],
        render_kw={"placeholder": "Jane Doe", "autocomplete": "name"},
    )
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=60),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Use letters, numbers, dots, dashes or underscores only.",
            ),
        ],
        render_kw={"placeholder": "jane.doe", "autocomplete": "username"},
    )
    email = StringField(
        "Email address",
        validators=[DataRequired(), Email(), Length(max=255)],
        render_kw={"placeholder": "jane@example.com", "autocomplete": "email"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128), _strong_password],
        render_kw={"placeholder": "At least 8 characters", "autocomplete": "new-password"},
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
        render_kw={"placeholder": "Repeat your password", "autocomplete": "new-password"},
    )
    submit = SubmitField("Create secure account")

    def validate_username(self, field):
        exists = User.query.filter(
            func.lower(User.username) == field.data.strip().lower()
        ).first()
        if exists:
            raise ValidationError("That username is already taken.")

    def validate_email(self, field):
        exists = User.query.filter(
            func.lower(User.email) == field.data.strip().lower()
        ).first()
        if exists:
            raise ValidationError("An account with that email already exists.")


class LoginForm(FlaskForm):
    identifier = StringField(
        "Username or email",
        validators=[DataRequired(), Length(max=255)],
        render_kw={"placeholder": "Username or email", "autocomplete": "username"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(max=128)],
        render_kw={"placeholder": "Your password", "autocomplete": "current-password"},
    )
    remember = BooleanField("Keep me signed in")
    submit = SubmitField("Sign in securely")


class ProfileForm(FlaskForm):
    full_name = StringField(
        "Full name", validators=[DataRequired(), Length(min=2, max=120)]
    )
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=60),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Use letters, numbers, dots, dashes or underscores only.",
            ),
        ],
    )
    email = StringField(
        "Email address", validators=[DataRequired(), Email(), Length(max=255)]
    )
    save = SubmitField("Save changes")

    def validate_username(self, field):
        query = User.query.filter(
            func.lower(User.username) == field.data.strip().lower()
        )
        if current_user.is_authenticated:
            query = query.filter(User.id != current_user.id)
        if query.first():
            raise ValidationError("That username is already taken.")

    def validate_email(self, field):
        query = User.query.filter(
            func.lower(User.email) == field.data.strip().lower()
        )
        if current_user.is_authenticated:
            query = query.filter(User.id != current_user.id)
        if query.first():
            raise ValidationError("An account with that email already exists.")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current password", validators=[DataRequired(), Length(max=128)]
    )
    new_password = PasswordField(
        "New password",
        validators=[DataRequired(), Length(min=8, max=128), _strong_password],
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    change_password = SubmitField("Update password")


class UploadForm(FlaskForm):
    file = FileField("Choose file", validators=[DataRequired()])
    submit = SubmitField("Encrypt & upload")


class ShareForm(FlaskForm):
    email = StringField(
        "Recipient email",
        validators=[DataRequired(), Email(), Length(max=255)],
        render_kw={"placeholder": "recipient@example.com"},
    )
    permission_type = SelectField(
        "Access permission",
        choices=[
            (PERMISSION_VIEW, PERMISSION_LABELS[PERMISSION_VIEW]),
            (PERMISSION_DOWNLOAD, PERMISSION_LABELS[PERMISSION_DOWNLOAD]),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Grant access")
