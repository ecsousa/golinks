CREATE SCHEMA IF NOT EXISTS golinks;

CREATE TABLE IF NOT EXISTS golinks.schema_migration (
    version CHAR(8) PRIMARY KEY,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER,
    success BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS golinks.users (
    user_id SERIAL PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL UNIQUE,
    user_secret VARCHAR(64) NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS golinks.links (
    link_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES golinks.users(user_id) ON DELETE CASCADE,
    link_keyword VARCHAR(32) NOT NULL,
    link_target VARCHAR(512) NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_links_user_keyword UNIQUE (user_id, link_keyword)
);

CREATE TABLE IF NOT EXISTS golinks.tags (
    tag_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES golinks.users(user_id) ON DELETE CASCADE,
    tag_name VARCHAR(32) NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tags_user_name UNIQUE (user_id, tag_name)
);

CREATE TABLE IF NOT EXISTS golinks.link_tags (
    link_id INTEGER NOT NULL REFERENCES golinks.links(link_id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES golinks.tags(tag_id) ON DELETE CASCADE,
    PRIMARY KEY (link_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_link_tags_tag_id ON golinks.link_tags(tag_id);
