CREATE TABLE IF NOT EXISTS email_addresses (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100) NOT NULL UNIQUE
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

CREATE TABLE IF NOT EXISTS list_admins (
    id SERIAL PRIMARY KEY,
    list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    user_email VARCHAR(100) NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    UNIQUE(list_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_lists_to_emails_list_id ON lists_to_emails(list_id);
CREATE INDEX IF NOT EXISTS idx_lists_to_emails_email_id ON lists_to_emails(email_address_id);
CREATE INDEX IF NOT EXISTS idx_list_admins_list_id ON list_admins(list_id);
CREATE INDEX IF NOT EXISTS idx_list_admins_user_email ON list_admins(user_email);
