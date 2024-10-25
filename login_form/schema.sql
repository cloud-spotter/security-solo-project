DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS post;

CREATE TABLE user (
  id TEXT PRIMARY KEY,  -- Changed from INTEGER to TEXT for UUID
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL CHECK(length(password) >= 60)
);

CREATE TABLE post (
  id TEXT PRIMARY KEY,  -- Also updated to UUID
  author_id TEXT NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  FOREIGN KEY (author_id) REFERENCES user (id)
);