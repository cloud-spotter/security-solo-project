from login_form.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

class User():
  
  @classmethod
  def create(cls, username, password):
    db = get_db()
    db.execute(
      "INSERT INTO user (username, password) VALUES (?, ?)", (username, password) # Use parameterised queries rather than string concatenation (for security)
    )
    db.commit()

  @classmethod
  def find_with_credentials(cls, username, password):
    db = get_db()
    user = db.execute(
      "SELECT id, username, password FROM user WHERE username = ? AND password = ?", (username, password) # Use parameterised queries rather than string concatenation (for security)
    ).fetchone()
    print(user)
    if user:
        return User(user['username'], user['password'], user['id'])
    else:
      return None

  @classmethod
  def find_by_id(cls, user_id):
    user = get_db().execute(
      'SELECT id, username, password FROM user WHERE id = ?', (user_id,)
    ).fetchone()
    if user:
      return User(user['username'], user['password'], user['id'])
    else:
      return None

  def __init__(self, username, password, id):
    self.username = username
    self.password = password
    self.id = id

