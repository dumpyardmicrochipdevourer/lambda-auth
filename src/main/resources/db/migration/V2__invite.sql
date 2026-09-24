CREATE TABLE invite (
    id         UUID        PRIMARY KEY,
    code       VARCHAR(64) NOT NULL UNIQUE,
    created_by UUID        NOT NULL REFERENCES app_user (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_by    UUID        REFERENCES app_user (id),
    used_at    TIMESTAMPTZ,
    CHECK ((used_by IS NULL) = (used_at IS NULL))
);

CREATE INDEX idx_invite_created_by ON invite (created_by, created_at DESC);
