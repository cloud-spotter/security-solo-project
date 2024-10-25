import sqlite3
import uuid
from werkzeug.security import check_password_hash, generate_password_hash
from login_form.db import get_db

class User():
    @staticmethod
    def generate_user_id():
        return str(uuid.uuid4())

    @classmethod
    def create(cls, username, password):
        if not username or not password:
            raise ValueError("Username and password are required")
            
        # Sanitize inputs
        safe_username = cls.sanitize_input(username)
        if not safe_username:
            raise ValueError("Invalid username format")
            
        # Generate UUID for user_id
        user_id = cls.generate_user_id()
        hashed_password = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO user (id, username, password) VALUES (?, ?, ?)',
                (user_id, safe_username, hashed_password)
            )
            db.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"User {username} is already registered.")

    @classmethod
    def find_by_id(cls, user_id):
        if not user_id or not isinstance(user_id, str):
            return None
            
        # Validate UUID format
        try:
            uuid.UUID(str(user_id))
        except ValueError:
            return None
            
        db = get_db()
        user = db.execute(
            'SELECT * FROM user WHERE id = ?',
            (user_id,)
        ).fetchone()
        
        if user:
            return User(user['username'], user['password'], user['id'])
        return None