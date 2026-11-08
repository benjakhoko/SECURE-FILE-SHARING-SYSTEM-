"""Custom Flask CLI commands: database setup, admin bootstrap, key generation."""

import re

import click
from flask import Flask
from sqlalchemy import func

from app.extensions import db
from app.models import ROLE_ADMIN, User
from app.security.encryption import generate_key

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,60}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def register_commands(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db():
        """Create all database tables (development / first run)."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("generate-key")
    def generate_encryption_key():
        """Generate a new AES-256 encryption key for .env."""
        click.echo(generate_key())

    @app.cli.command("create-admin")
    @click.option("--full-name", prompt="Full name", help="Administrator full name.")
    @click.option("--username", prompt="Username", help="Administrator username.")
    @click.option("--email", prompt="Email", help="Administrator email address.")
    @click.option(
        "--password",
        prompt="Password",
        hide_input=True,
        confirmation_prompt=True,
        help="Administrator password (min 8 characters).",
    )
    def create_admin(full_name: str, username: str, email: str, password: str):
        """Create the first administrator account securely."""
        full_name = full_name.strip()
        username = username.strip()
        email = email.strip().lower()

        if len(full_name) < 2:
            raise click.ClickException("Full name must be at least 2 characters.")
        if not USERNAME_RE.match(username):
            raise click.ClickException(
                "Username must be 3-60 characters: letters, numbers, dot, dash, underscore."
            )
        if not EMAIL_RE.match(email):
            raise click.ClickException("Please provide a valid email address.")
        if len(password) < 8 or not any(c.isalpha() for c in password) or not any(
            c.isdigit() for c in password
        ):
            raise click.ClickException(
                "Password must be at least 8 characters and include a letter and a number."
            )

        if User.query.filter(func.lower(User.username) == username.lower()).first():
            raise click.ClickException("That username is already taken.")
        if User.query.filter(func.lower(User.email) == email).first():
            raise click.ClickException("An account with that email already exists.")

        user = User(
            full_name=full_name,
            username=username,
            email=email,
            role=ROLE_ADMIN,
            is_active=True,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Administrator '{username}' created successfully.")
