CREATE TABLE user_access (
    user_id UUID        NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    service VARCHAR(32) NOT NULL,
    PRIMARY KEY (user_id, service)
);
