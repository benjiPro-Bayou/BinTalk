package cache

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/internal/config"
)

const connectAttempts = 15

// NewRedisClient creates a Redis client and waits until the server is reachable.
func NewRedisClient(cfg config.RedisConfig) *redis.Client {
	opts := &redis.Options{
		Addr:     net.JoinHostPort(cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
	}
	if cfg.TLSEnable {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	client := redis.NewClient(opts)

	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := client.Ping(ctx).Err()
		cancel()
		if err == nil {
			return client
		}
		if attempt == connectAttempts {
			logrus.Fatalf("Failed to connect to Redis at %s: %v", opts.Addr, err)
		}
		logrus.Warnf("Redis not ready (attempt %d/%d): %v", attempt, connectAttempts, err)
		time.Sleep(2 * time.Second)
	}
}
