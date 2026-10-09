package handlers

import (
	"context"
	"time"
)

const maintenanceInterval = time.Hour

// RunMaintenance periodically deletes expired authentication state (refresh tokens and password
// reset links), which is otherwise only removed when used, and expires companies whose
// subscription has ended. It returns when ctx is cancelled.
func RunMaintenance(ctx context.Context, deps *Dependencies) {
	ticker := time.NewTicker(maintenanceInterval)
	defer ticker.Stop()
	for {
		cleanupExpiredAuthState(ctx, deps)
		expireCompanies(ctx, deps)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func cleanupExpiredAuthState(ctx context.Context, deps *Dependencies) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for _, q := range []struct{ what, sql string }{
		{"expired sessions", `DELETE FROM user_sessions WHERE expires_at < NOW()`},
		// Kept a week after expiry so recent reset activity can still be investigated.
		{"expired password resets", `DELETE FROM password_resets WHERE expires_at < NOW() - INTERVAL '7 days'`},
	} {
		res, err := deps.DB.ExecContext(ctx, q.sql)
		if err != nil {
			if ctx.Err() == nil {
				deps.Logger.WithError(err).Warnf("Failed to delete %s", q.what)
			}
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			deps.Logger.Infof("Deleted %d %s", n, q.what)
		}
	}
}
