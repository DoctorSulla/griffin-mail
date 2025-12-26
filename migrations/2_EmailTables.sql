CREATE TABLE IF NOT EXISTS email_addresses (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(320) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS lists (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(300)
);

CREATE TABLE IF NOT EXISTS lists_to_emails (
    id SERIAL PRIMARY KEY,
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    email_address_id INTEGER NOT NULL REFERENCES email_addresses(id) ON DELETE CASCADE,
    UNIQUE(list_id, email_address_id)
);

CREATE TABLE IF NOT EXISTS list_permissions (
    id SERIAL PRIMARY KEY,
    permission VARCHAR(100) NOT NULL,
    UNIQUE(permission)
);

CREATE TABLE IF NOT EXISTS list_user_permissions (
    id SERIAL PRIMARY KEY,
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    user_email VARCHAR(320) NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES list_permissions(id) ON DELETE CASCADE,
    UNIQUE(list_id, user_email, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_lists_to_emails_list_id ON lists_to_emails(list_id);
CREATE INDEX IF NOT EXISTS idx_lists_to_emails_email_id ON lists_to_emails(email_address_id);
CREATE INDEX IF NOT EXISTS idx_list_user_permissions_list_id ON list_user_permissions(list_id);
CREATE INDEX IF NOT EXISTS idx_list_user_permissions_user_email ON list_user_permissions(user_email);
