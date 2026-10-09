package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/internal/config"
	"github.com/bintalk/bintalk-clone/internal/handlers"
	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/services"
	"github.com/bintalk/bintalk-clone/migrations"
	"github.com/bintalk/bintalk-clone/pkg/cache"
	"github.com/bintalk/bintalk-clone/pkg/chapa"
	"github.com/bintalk/bintalk-clone/pkg/db"
	"github.com/bintalk/bintalk-clone/pkg/kafka"
	"github.com/bintalk/bintalk-clone/pkg/mail"
	"github.com/bintalk/bintalk-clone/pkg/vault"
)

const (
	// shutdownTimeout bounds how long in-flight requests may finish after SIGTERM.
	shutdownTimeout = 30 * time.Second
	// Per-request deadlines: JSON routes are short; file transfers get long enough for the
	// largest upload on a slow link.
	requestTimeout  = 30 * time.Second
	transferTimeout = 15 * time.Minute
)

var logger = logrus.New()

func init() {
	_ = godotenv.Load() // optional: a missing .env is fine
	logger.SetFormatter(&logrus.JSONFormatter{})
}

// loadConfig loads and validates the configuration and applies LOG_LEVEL, exiting on errors.
func loadConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("Invalid configuration: %v", err)
	}
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.Fatalf("Invalid LOG_LEVEL %q: %v", cfg.LogLevel, err)
	}
	logger.SetLevel(level)
	return cfg
}

func main() {
	if len(os.Args) > 1 {
		runCommand(os.Args[1:])
		return
	}

	logger.Info("=== BinTalk API Server Starting ===")

	cfg := loadConfig()
	logger.WithField("environment", cfg.Environment).Info("Configuration loaded successfully")
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	vaultClient, err := vault.NewVaultClient(&vault.VaultConfig{Address: cfg.Vault.Address, Token: cfg.Vault.Token}, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize Vault client: %v", err)
	}
	defer vaultClient.Close()
	logger.Info("Connected to HashiCorp Vault")

	database := db.NewPostgres(cfg.Database)
	defer database.Close()
	logger.Info("Connected to PostgreSQL")

	applied, err := migrations.Apply(database)
	if err != nil {
		logger.Fatalf("Failed to apply database migrations: %v", err)
	}
	for _, name := range applied {
		logger.Infof("Applied database migration %s", name)
	}

	redisClient := cache.NewRedisClient(cfg.Redis)
	defer redisClient.Close()
	logger.Info("Connected to Redis")

	kafkaProducer := kafka.NewProducer(cfg.Kafka)
	defer kafkaProducer.Close() // flushes buffered events
	logger.Info("Connected to Kafka")

	encryptionService := services.NewEncryptionService(vaultClient, database, logger)
	defer encryptionService.Close()
	logger.Info("Encryption service initialized")

	// gin.New rather than gin.Default: Gin's default logger prints raw query strings.
	// ErrorHandlingMiddleware recovers panics.
	router := gin.New()
	if err := router.SetTrustedProxies(cfg.Security.TrustedProxies); err != nil {
		logger.Fatalf("Invalid TRUSTED_PROXIES: %v", err)
	}

	router.Use(middleware.ErrorHandlingMiddleware())
	router.Use(middleware.LoggingMiddleware(logger))
	router.Use(middleware.CORSMiddleware(cfg.CORS.AllowedOrigins, cfg.CORS.AllowedMethods))
	router.Use(middleware.DeadlineMiddleware(requestTimeout, map[string]time.Duration{
		"/api/v1/files/upload":        transferTimeout,
		"/api/v1/files/:id":           transferTimeout,
		"/api/v1/files/:id/thumbnail": transferTimeout,
		"/ws/chat/:userId":            0, // the WebSocket manages its own deadlines
	}))
	router.Use(middleware.BodyLimitMiddleware(cfg.Security.MaxJSONBodySize, "/api/v1/files/upload"))
	router.Use(middleware.RateLimitMiddleware(redisClient, cfg.Security.RateLimitRequests, cfg.Security.RateLimitWindow))

	headerEncryptionMiddleware := middleware.NewHeaderEncryptionMiddleware(encryptionService, vaultClient, logger)
	router.Use(headerEncryptionMiddleware.DecryptHeaders())
	router.Use(headerEncryptionMiddleware.EncryptResponse())

	// Liveness: the process is up.
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "version": "1.0.0", "service": "bintalk-api"})
	})
	// Readiness: the dependencies needed to serve requests answer.
	router.GET("/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		checks := gin.H{"database": "ok", "redis": "ok", "encryption": "ok"}
		ready := true
		if err := database.PingContext(ctx); err != nil {
			checks["database"], ready = "unavailable", false
		}
		if err := redisClient.Ping(ctx).Err(); err != nil {
			checks["redis"], ready = "unavailable", false
		}
		if err := encryptionService.Ready(); err != nil {
			checks["encryption"], ready = "no active data key", false
		}
		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"ready": ready, "checks": checks})
	})

	deps := &handlers.Dependencies{
		Config:            cfg,
		Mailer:            mail.New(cfg.Email),
		DB:                database,
		Redis:             redisClient,
		Kafka:             kafkaProducer,
		Logger:            logger,
		VaultClient:       vaultClient,
		EncryptionService: encryptionService,
		Chapa:             chapa.New(cfg.Billing.ChapaBaseURL, cfg.Billing.ChapaSecretKey),
	}
	if !deps.Chapa.Configured() {
		logger.Warn("CHAPA_SECRET_KEY is not set: new companies wait for a platform admin's approval instead of paying online")
	}

	handlers.EnsureBootstrapAdmin(context.Background(), deps)
	initializeRoutes(router, deps)

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
	}

	// No global ReadTimeout/WriteTimeout: they bound the whole request including the body and
	// would cut off large uploads and downloads. DeadlineMiddleware sets per-route deadlines.
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go handlers.RunMaintenance(ctx, deps)

	serveErr := make(chan error, 1)
	go func() {
		logger.Infof("Starting HTTPS server on %s", srv.Addr)
		serveErr <- srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("Server error: %v", err)
		}
	case <-ctx.Done():
		logger.Info("Shutting down: finishing in-flight requests")
		// WebSockets are hijacked connections that Shutdown does not track; close them first so
		// clients reconnect to the next instance.
		deps.Hub().CloseAll()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.WithError(err).Warn("Graceful shutdown did not finish in time")
		}
		logger.Info("Server stopped")
	}
}

func initializeRoutes(router *gin.Engine, deps *handlers.Dependencies) {
	// Public routes
	public := router.Group("/api/v1")
	{
		public.POST("/auth/register", handlers.NewAuthHandler(deps).Register)
		public.POST("/auth/login", handlers.NewAuthHandler(deps).Login)
		public.POST("/auth/refresh", handlers.NewAuthHandler(deps).Refresh)
		public.POST("/auth/forgot-password", handlers.NewAuthHandler(deps).ForgotPassword)
		public.POST("/auth/reset-password", handlers.NewAuthHandler(deps).ResetPassword)
		public.GET("/encryption/public-key", handlers.NewEncryptionHandler(deps.EncryptionService).GetPublicKey)

		// Landing page: plans, company sign-up, payments and invitations
		companyHandler := handlers.NewCompanyHandler(deps)
		public.GET("/public/plans", companyHandler.PublicPlans)
		public.POST("/public/signup", companyHandler.Signup)
		public.POST("/public/checkout", companyHandler.PublicCheckout)
		public.GET("/public/payments/:txRef", companyHandler.PaymentStatus)
		public.GET("/public/payments/chapa/callback", companyHandler.ChapaCallback)
		public.POST("/public/payments/chapa/callback", companyHandler.ChapaCallback)
		public.POST("/public/payments/chapa/webhook", companyHandler.ChapaWebhook)
		public.GET("/public/invitations/:token", companyHandler.InvitationInfo)
	}

	// Protected routes
	protected := router.Group("/api/v1")
	protected.Use(middleware.AuthMiddleware(deps.Redis, deps.DB))
	{
		// Account
		authHandler := handlers.NewAuthHandler(deps)
		protected.GET("/auth/me", authHandler.Me)
		protected.POST("/auth/change-password", authHandler.ChangePassword)
		protected.POST("/auth/logout", authHandler.Logout)

		// Single-use ticket for opening the WebSocket (keeps access tokens out of URLs and logs)
		wsHandler := handlers.NewWebSocketHandler(deps)
		protected.POST("/ws-ticket", wsHandler.IssueTicket)

		// Voice & video calls (WebRTC signaling goes over the WebSocket)
		callHandler := handlers.NewCallHandler(deps)
		protected.POST("/calls", callHandler.StartCall)
		protected.GET("/calls/active", callHandler.ActiveCalls)
		protected.POST("/calls/:id/join", callHandler.JoinCall)
		protected.POST("/calls/:id/decline", callHandler.DeclineCall)
		protected.POST("/calls/:id/leave", callHandler.LeaveCall)
		protected.POST("/calls/:id/mute", callHandler.MuteParticipant)

		// Presence: the status a user chooses (auto | away | offline); live updates go over the WebSocket
		protected.PUT("/presence", handlers.NewPresenceHandler(deps).SetPreference)

		// Abuse reports
		protected.POST("/reports", handlers.NewReportHandler(deps).CreateReport)

		// User routes
		userHandler := handlers.NewUserHandler(deps)
		protected.GET("/users/:id", userHandler.GetUser)
		protected.PUT("/users/:id", userHandler.UpdateUser)
		protected.GET("/users/search", userHandler.SearchUsers)

		// Message routes
		msgHandler := handlers.NewMessageHandler(deps)
		protected.GET("/conversations", msgHandler.ListConversations)
		protected.POST("/messages", msgHandler.SendMessage)
		protected.GET("/messages/:id", msgHandler.GetMessages)
		protected.POST("/messages/:id/read", msgHandler.MarkRead)
		protected.GET("/messages/:id/reads", msgHandler.GetMessageReads)
		protected.GET("/messages/:id/thread", msgHandler.GetThread)
		protected.POST("/messages/:id/thread/read", msgHandler.MarkThreadRead)
		protected.PUT("/messages/:id", msgHandler.EditMessage)
		protected.DELETE("/messages/:id", msgHandler.DeleteMessage)

		// Group routes
		grpHandler := handlers.NewGroupHandler(deps)
		protected.GET("/groups", grpHandler.ListGroups)
		protected.POST("/groups", grpHandler.CreateGroup)
		protected.GET("/groups/:id", grpHandler.GetGroup)
		protected.PUT("/groups/:id", grpHandler.UpdateGroup)
		protected.POST("/groups/:id/members", grpHandler.AddMember)
		protected.DELETE("/groups/:id/members/:userId", grpHandler.RemoveMember)
		protected.POST("/groups/:id/join", grpHandler.JoinChannel)
		protected.POST("/groups/:id/leave", grpHandler.LeaveGroup)
		protected.GET("/channels", grpHandler.BrowseChannels)

		// File routes
		fileHandler := handlers.NewFileHandler(deps)
		protected.POST("/files/upload", fileHandler.UploadFile)
		protected.GET("/files/:id", fileHandler.DownloadFile)
		protected.GET("/files/:id/thumbnail", fileHandler.Thumbnail)
		protected.DELETE("/files/:id", fileHandler.DeleteFile)

		// Encryption routes
		encHandler := handlers.NewEncryptionHandler(deps.EncryptionService)
		protected.POST("/encryption/encrypt", encHandler.EncryptData)
		protected.POST("/encryption/decrypt", encHandler.DecryptData)
		protected.GET("/encryption/status", encHandler.GetEncryptionSummary)
	}

	// Admin console: company owners and admins manage their company; platform admins see all
	// companies (handlers scope every query to the caller's company otherwise).
	admin := router.Group("/api/v1/admin")
	admin.Use(middleware.AuthMiddleware(deps.Redis, deps.DB), handlers.RequireCompanyAdmin(deps))
	{
		adminHandler := handlers.NewAdminHandler(deps)
		companyHandler := handlers.NewCompanyHandler(deps)
		admin.GET("/company", companyHandler.MyCompany)
		admin.POST("/company/checkout", companyHandler.RenewCompany)
		admin.GET("/invitations", companyHandler.ListInvitations)
		admin.POST("/invitations", companyHandler.CreateInvitation)
		admin.DELETE("/invitations/:id", companyHandler.RevokeInvitation)
		admin.GET("/stats", adminHandler.Stats)
		admin.GET("/users", adminHandler.ListUsers)
		admin.PUT("/users/:id", adminHandler.UpdateUser)
		admin.POST("/users/:id/reset-password", adminHandler.ResetUserPassword)
		admin.GET("/reports", adminHandler.ListReports)
		admin.PUT("/reports/:id", adminHandler.UpdateReport)
		admin.GET("/audit", adminHandler.ListAudit)
	}

	// Platform administration: companies, plans, payments, Vault status (platform admins only)
	platform := router.Group("/api/v1/platform")
	platform.Use(middleware.AuthMiddleware(deps.Redis, deps.DB), middleware.RequireAdmin(deps.DB))
	{
		companyHandler := handlers.NewCompanyHandler(deps)
		platform.GET("/companies", companyHandler.ListCompanies)
		platform.POST("/companies", companyHandler.CreateCompany)
		platform.PUT("/companies/:id", companyHandler.UpdateCompany)
		platform.GET("/plans", companyHandler.PlatformPlans)
		platform.POST("/plans", companyHandler.CreatePlan)
		platform.PUT("/plans/:id", companyHandler.UpdatePlan)
		platform.GET("/payments", companyHandler.ListPayments)
		platform.GET("/encryption/status", handlers.NewEncryptionHandler(deps.EncryptionService).GetEncryptionStatus)
	}

	// WebSocket route for real-time messaging
	router.GET("/ws/chat/:userId", handlers.NewWebSocketHandler(deps).HandleConnection)

	deps.Logger.Info("Routes initialized successfully")
}
