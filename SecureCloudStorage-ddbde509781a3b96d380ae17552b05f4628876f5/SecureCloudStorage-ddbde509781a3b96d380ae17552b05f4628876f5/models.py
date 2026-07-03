from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default='user'
    )

    mfa_secret = db.Column(
        db.String(100)
    )


class File(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(255)
    )

    encrypted_path = db.Column(
        db.String(255)
    )

    owner_id = db.Column(
        db.Integer
    )

    upload_date = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )