-- +goose Up
-- +goose StatementBegin

-- username was initially added as NOT NULL by mistake; the column is optional
-- (the partial unique index already assumed NULLs are allowed).
ALTER TABLE users ALTER COLUMN username DROP NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE users ALTER COLUMN username SET NOT NULL;

-- +goose StatementEnd
