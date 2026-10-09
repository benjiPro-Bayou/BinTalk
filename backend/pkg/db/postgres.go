package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/internal/config"
)

const connectAttempts = 15

// NewPostgres opens a PostgreSQL connection pool and waits until the database is reachable.
func NewPostgres(cfg config.DatabaseConfig) *sql.DB {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode,
	)

	database, err := sql.Open("postgres", dsn)
	if err != nil {
		logrus.Fatalf("Failed to open PostgreSQL connection: %v", err)
	}

	database.SetMaxOpenConns(cfg.MaxConnections)
	database.SetMaxIdleConns(cfg.MaxConnections / 2)
	database.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	database.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	for attempt := 1; ; attempt++ {
		if err = database.Ping(); err == nil {
			return database
		}
		if attempt == connectAttempts {
			logrus.Fatalf("Failed to connect to PostgreSQL at %s:%s: %v", cfg.Host, cfg.Port, err)
		}
		logrus.Warnf("PostgreSQL not ready (attempt %d/%d): %v", attempt, connectAttempts, err)
		time.Sleep(2 * time.Second)
	}
}
