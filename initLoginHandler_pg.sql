CREATE TABLE IF NOT EXISTS users (id SERIAL, username TEXT UNIQUE NOT NULL, hashed_pass TEXT, email TEXT);

