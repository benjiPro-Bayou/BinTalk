package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// CORSMiddleware allows the given origins ("*" allows any).
// Authentication uses bearer tokens rather than cookies, so credentials are not enabled.
func CORSMiddleware(origins []string, methods string) gin.HandlerFunc {
	allowed := map[string]bool{}
	allowAny := false
	for _, origin := range origins {
		if origin == "*" {
			allowAny = true
		}
		allowed[origin] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (allowAny || allowed[origin]) {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", methods)
			if requested := c.GetHeader("Access-Control-Request-Headers"); requested != "" {
				h.Set("Access-Control-Allow-Headers", requested)
			}
			h.Set("Access-Control-Expose-Headers", "X-Response-Encrypted, X-RateLimit-Limit, X-RateLimit-Remaining")
			h.Set("Access-Control-Max-Age", "3600")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// ErrorHandlingMiddleware turns panics and unhandled handler errors into JSON 500 responses.
func ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorf("panic handling %s %s: %v", c.Request.Method, c.Request.URL.Path, r)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
		}()

		c.Next()

		if len(c.Errors) > 0 && !c.Writer.Written() {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
	}
}

// LoggingMiddleware writes one structured log line per request.
func LoggingMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		fields := logrus.Fields{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"latency_ms": time.Since(start).Milliseconds(),
			"client_ip":  c.ClientIP(),
		}
		if userID := GetUserID(c); userID != uuid.Nil {
			fields["user_id"] = userID.String()
		}
		if len(c.Errors) > 0 {
			fields["errors"] = c.Errors.String()
		}

		entry := logger.WithFields(fields)
		switch status := c.Writer.Status(); {
		case status >= 500:
			entry.Error("request failed")
		case status >= 400:
			entry.Warn("request rejected")
		default:
			entry.Info("request completed")
		}
	}
}

// DeadlineMiddleware bounds how long reading the request and writing the response may take: def
// for every route, or the override for a route pattern (0 means no deadline). It replaces
// http.Server's ReadTimeout/WriteTimeout, which would cut off large file transfers.
func DeadlineMiddleware(def time.Duration, overrides map[string]time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		d, ok := overrides[c.FullPath()]
		if !ok {
			d = def
		}
		if d > 0 {
			rc := http.NewResponseController(c.Writer)
			deadline := time.Now().Add(d)
			_ = rc.SetReadDeadline(deadline)
			_ = rc.SetWriteDeadline(deadline)
		}
		c.Next()
	}
}

// BodyLimitMiddleware caps request bodies at limit bytes, except on the paths in exempt (which
// set their own limits, e.g. file uploads).
func BodyLimitMiddleware(limit int64, exempt ...string) gin.HandlerFunc {
	skip := map[string]bool{}
	for _, path := range exempt {
		skip[path] = true
	}
	return func(c *gin.Context) {
		if c.Request.Body != nil && !skip[c.Request.URL.Path] {
			if c.Request.ContentLength > limit {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body is too large"})
				return
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

// RateLimitMiddleware limits each client IP to limit requests per window using a fixed window
// counter in Redis. If Redis is unavailable, requests are allowed.
func RateLimitMiddleware(rdb *redis.Client, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
			c.Next()
			return
		}

		windowStart := time.Now().Truncate(window).Unix()
		key := fmt.Sprintf("ratelimit:%s:%d", c.ClientIP(), windowStart)

		ctx, cancel := context.WithTimeout(c.Request.Context(), 500*time.Millisecond)
		pipe := rdb.TxPipeline()
		incr := pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, window)
		_, err := pipe.Exec(ctx)
		cancel()
		if err != nil {
			c.Next()
			return
		}

		count := int(incr.Val())
		remaining := limit - count
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if count > limit {
			retryAfter := windowStart + int64(window.Seconds()) - time.Now().Unix()
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}
