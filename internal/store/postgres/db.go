package postgres

import (
	"database/sql"
	"log/slog"

	_ "github.com/lib/pq"
)

// InitDB initializes the postgres database connection pool
func InitDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	slog.Info("Connected to PostgreSQL successfully")
	return db, nil
}
