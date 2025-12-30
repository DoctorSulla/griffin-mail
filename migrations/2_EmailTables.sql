CREATE TABLE IF NOT EXISTS recipients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(320) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS lists (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(300) NOT NULL
);

CREATE TABLE IF NOT EXISTS lists_to_recipients (
    id SERIAL PRIMARY KEY,
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
    UNIQUE(list_id, recipient_id)
);

CREATE TABLE IF NOT EXISTS list_permissions (
    permission VARCHAR(100) PRIMARY KEY
);

INSERT INTO list_permissions (permission) VALUES ('read'), ('write'), ('send')
ON CONFLICT (permission) DO NOTHING;

CREATE TABLE IF NOT EXISTS list_user_permissions (
    id SERIAL PRIMARY KEY,
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    user_email VARCHAR(320) NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL REFERENCES list_permissions(permission) ON DELETE CASCADE,
    UNIQUE(list_id, user_email, permission)
);

CREATE INDEX IF NOT EXISTS idx_lists_to_recipients_list_id ON lists_to_recipients(list_id);
CREATE INDEX IF NOT EXISTS idx_lists_to_recipients_email_id ON lists_to_recipients(recipient_id);
CREATE INDEX IF NOT EXISTS idx_list_user_permissions_list_id ON list_user_permissions(list_id);
CREATE INDEX IF NOT EXISTS idx_list_user_permissions_user_email ON list_user_permissions(user_email);
