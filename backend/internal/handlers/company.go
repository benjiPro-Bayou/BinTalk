package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/bintalk/bintalk-clone/internal/models"
	"github.com/bintalk/bintalk-clone/pkg/chapa"
)

// Company lifecycle:
//
//	sign-up (landing page) → pending_payment → Chapa checkout → payment verified →
//	    active (or pending_approval when COMPANY_REQUIRE_APPROVAL is set) → expired when the paid
//	    period plus the grace period ends → renewed by paying again.
//
// Without a Chapa key, new companies wait in pending_approval for a platform admin. Platform
// admins can also create, approve, suspend or extend companies directly.

const (
	invitationTTL = 7 * 24 * time.Hour
	signupsPerIP  = 10 // per hour
)

var (
	slugCleaner  = regexp.MustCompile(`[^a-z0-9]+`)
	slugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$`)
	chapaPhone   = regexp.MustCompile(`^0[79][0-9]{8}$`)
	chapaUnsafe  = regexp.MustCompile(`[^A-Za-z0-9 ._-]+`)
	planCodeRule = regexp.MustCompile(`^[a-z0-9_-]{2,50}$`)
)

// CompanyHandler serves company sign-up, payments, invitations, billing and platform management.
type CompanyHandler struct {
	deps *Dependencies
}

// NewCompanyHandler creates a CompanyHandler.
func NewCompanyHandler(deps *Dependencies) *CompanyHandler {
	return &CompanyHandler{deps: deps}
}

// ---------- plans ----------

func listPlans(ctx context.Context, db *sql.DB, activeOnly bool) ([]models.Plan, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+planColumns+` FROM plans p
		WHERE NOT $1 OR p.is_active ORDER BY p.sort_order, p.price_monthly`, activeOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := []models.Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		plans = append(plans, *p)
	}
	return plans, rows.Err()
}

func loadPlanByCode(ctx context.Context, q queryer, code string) (*models.Plan, error) {
	p, err := scanPlan(q.QueryRowContext(ctx, `SELECT `+planColumns+` FROM plans p WHERE p.code = $1`, code))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return p, err
}

// PublicPlans lists the plans offered on the landing page (GET /public/plans).
func (h *CompanyHandler) PublicPlans(c *gin.Context) {
	plans, err := listPlans(c.Request.Context(), h.deps.DB, true)
	if err != nil {
		h.deps.internalError(c, err, "list plans")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"plans":             plans,
		"online_payment":    h.deps.Chapa.Configured(),
		"requires_approval": h.deps.Config.Billing.RequireApproval || !h.deps.Chapa.Configured(),
	})
}

// ---------- sign-up ----------

// Signup registers a company and its owner from the landing page (POST /public/signup), then
// starts a Chapa checkout. Without online payment, the company waits for a platform admin.
func (h *CompanyHandler) Signup(c *gin.Context) {
	var req struct {
		CompanyName  string `json:"company_name" binding:"required,max=150"`
		Slug         string `json:"slug" binding:"max=60"`
		Phone        string `json:"phone" binding:"max=30"`
		PlanCode     string `json:"plan_code" binding:"required"`
		BillingCycle string `json:"billing_cycle" binding:"required,oneof=monthly yearly"`
		FullName     string `json:"full_name" binding:"required"`
		Username     string `json:"username" binding:"required"`
		Email        string `json:"email" binding:"required,email"`
		Password     string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ctx := c.Request.Context()
	auth := &AuthHandler{deps: h.deps}
	if auth.overLimit(ctx, "signup:ip:"+c.ClientIP(), signupsPerIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many sign-ups from this network; try again later"})
		return
	}

	name := strings.TrimSpace(req.CompanyName)
	if len(name) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "company name is required"})
		return
	}
	phone := strings.TrimSpace(req.Phone)
	if phone != "" && !chapaPhone.MatchString(phone) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone must be 10 digits starting with 09 or 07"})
		return
	}
	owner := newAccount{Username: req.Username, Email: req.Email, FullName: req.FullName, Password: req.Password,
		CompanyRole: models.CompanyOwner}
	if msg := validateAccount(&owner); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	plan, err := loadPlanByCode(ctx, h.deps.DB, req.PlanCode)
	if errors.Is(err, errNotFound) || (err == nil && !plan.IsActive) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown plan"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load plan")
		return
	}

	online := h.deps.Chapa.Configured()
	status := models.CompanyPendingPayment
	if !online {
		status = models.CompanyPendingApproval
	}

	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()
	slug, err := uniqueSlug(ctx, tx, firstNonEmpty(strings.TrimSpace(req.Slug), name))
	if err != nil {
		h.deps.internalError(c, err, "choose slug")
		return
	}
	var companyID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO companies (name, slug, status, plan_id, billing_cycle, contact_email, contact_phone)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')) RETURNING id`,
		name, slug, status, plan.ID, req.BillingCycle, owner.Email, phone).Scan(&companyID); err != nil {
		h.deps.internalError(c, err, "create company")
		return
	}
	owner.CompanyID = companyID
	user, err := createUser(ctx, tx, owner)
	if errors.Is(err, errAccountTaken) {
		c.JSON(http.StatusConflict, gin.H{"error": "that username or email already has a BinTalk account"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "create owner")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "create company")
		return
	}
	recordAudit(ctx, h.deps, c, user.ID, "create", "company", companyID,
		gin.H{"event": "company_signup", "company": name, "plan": plan.Code, "billing_cycle": req.BillingCycle})

	company, err := loadCompany(ctx, h.deps.DB, companyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	resp := gin.H{"company": company}
	if online {
		payment, checkoutURL, err := h.startCheckout(ctx, company, plan, req.BillingCycle, user)
		if err != nil {
			// The company exists; the owner can finish paying later from the landing page.
			h.deps.Logger.WithError(err).Error("Failed to start Chapa checkout")
			resp["payment_error"] = "The payment page could not be opened. Try again with “Complete payment” on the home page."
		} else {
			resp["checkout_url"], resp["tx_ref"] = checkoutURL, payment.TxRef
		}
	}
	c.JSON(http.StatusCreated, resp)
}

// uniqueSlug turns a name into a URL-friendly identifier that no company uses yet.
func uniqueSlug(ctx context.Context, q queryer, name string) (string, error) {
	base := strings.Trim(slugCleaner.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(base) > 50 {
		base = strings.Trim(base[:50], "-")
	}
	if len(base) < 3 {
		base = "team-" + base
	}
	slug := base
	for i := 0; i < 5; i++ {
		var taken bool
		if err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM companies WHERE slug = $1)`, slug).Scan(&taken); err != nil {
			return "", err
		}
		if !taken && slugPattern.MatchString(slug) {
			return slug, nil
		}
		slug = base + "-" + randomHex(2)
	}
	return base + "-" + randomHex(4), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------- payments ----------

const paymentColumns = `pay.id, pay.company_id, co.name, pay.plan_id, pl.name, pay.billing_cycle, pay.tx_ref,
	pay.amount::float8, pay.currency, pay.status, pay.provider, COALESCE(pay.provider_reference, ''),
	pay.created_at, pay.verified_at`

const paymentFrom = ` FROM payments pay JOIN companies co ON co.id = pay.company_id JOIN plans pl ON pl.id = pay.plan_id`

func scanPayment(row rowScanner) (*models.Payment, error) {
	var p models.Payment
	err := row.Scan(&p.ID, &p.CompanyID, &p.CompanyName, &p.PlanID, &p.PlanName, &p.BillingCycle, &p.TxRef,
		&p.Amount, &p.Currency, &p.Status, &p.Provider, &p.ProviderReference, &p.CreatedAt, &p.VerifiedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// startCheckout records a pending payment and opens a Chapa hosted checkout for it.
func (h *CompanyHandler) startCheckout(ctx context.Context, company *models.Company, plan *models.Plan,
	cycle string, payer *models.User) (*models.Payment, string, error) {
	amount := plan.Price(cycle)
	if amount <= 0 {
		return nil, "", errors.New("the plan has no price for this billing cycle")
	}
	txRef := "btk-" + randomHex(12)
	var paymentID uuid.UUID
	if err := h.deps.DB.QueryRowContext(ctx, `
		INSERT INTO payments (company_id, plan_id, billing_cycle, tx_ref, amount, currency)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		company.ID, plan.ID, cycle, txRef, amount, plan.Currency).Scan(&paymentID); err != nil {
		return nil, "", err
	}

	first, last, _ := strings.Cut(strings.TrimSpace(payer.FullName), " ")
	req := chapa.InitializeRequest{
		Amount: fmt.Sprintf("%.2f", amount), Currency: plan.Currency, Email: payer.Email,
		FirstName: first, LastName: strings.TrimSpace(last), TxRef: txRef,
		CallbackURL: h.deps.Config.Billing.AppBaseURL + "/api/v1/public/payments/chapa/callback",
		ReturnURL:   h.deps.Config.Billing.AppBaseURL + "/#payment=" + txRef,
	}
	if chapaPhone.MatchString(company.ContactPhone) {
		req.PhoneNumber = company.ContactPhone
	}
	req.Customization.Title = "BinTalk"
	req.Customization.Description = strings.TrimSpace(chapaUnsafe.ReplaceAllString(
		fmt.Sprintf("BinTalk %s plan %s for %s", plan.Name, cycle, company.Name), " "))

	checkoutURL, err := h.deps.Chapa.Initialize(ctx, req)
	if err != nil {
		_, _ = h.deps.DB.ExecContext(ctx, `UPDATE payments SET status = 'failed' WHERE id = $1`, paymentID)
		return nil, "", err
	}
	if _, err := h.deps.DB.ExecContext(ctx, `UPDATE payments SET checkout_url = $2 WHERE id = $1`, paymentID, checkoutURL); err != nil {
		return nil, "", err
	}
	return &models.Payment{ID: paymentID, TxRef: txRef, Amount: amount, Currency: plan.Currency, Status: "pending"}, checkoutURL, nil
}

// errUnknownPayment is returned by settlePayment for a tx_ref BinTalk did not create.
var errUnknownPayment = errors.New("unknown payment")

// settlePayment verifies a pending payment with Chapa and, once it succeeded, extends the
// company's subscription and activates it. It is idempotent: callbacks, webhooks and the
// customer's browser may all trigger it.
func settlePayment(ctx context.Context, deps *Dependencies, txRef string) (*models.Payment, error) {
	payment, err := scanPayment(deps.DB.QueryRowContext(ctx, `SELECT `+paymentColumns+paymentFrom+` WHERE pay.tx_ref = $1`, txRef))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errUnknownPayment
	}
	if err != nil || payment.Status != "pending" {
		return payment, err
	}

	// Ask Chapa before taking any lock: it is the source of truth.
	v, err := deps.Chapa.Verify(ctx, txRef)
	if err != nil {
		return nil, err
	}
	outcome := "pending"
	switch {
	case v.Status == "success" && v.TxRef == txRef && strings.EqualFold(v.Currency, payment.Currency) &&
		v.Amount+0.005 >= payment.Amount:
		outcome = "success"
	case v.Status == "success":
		deps.Logger.WithField("tx_ref", txRef).WithField("amount", v.Amount).WithField("currency", v.Currency).
			Error("Chapa reported a payment that does not match the expected amount or currency")
		outcome = "failed"
	case v.Status == "failed":
		outcome = "failed"
	}
	if outcome == "pending" {
		return payment, nil
	}

	tx, err := deps.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM payments WHERE id = $1 FOR UPDATE`, payment.ID).Scan(&current); err != nil {
		return nil, err
	}
	if current != "pending" { // settled concurrently
		return scanPayment(deps.DB.QueryRowContext(ctx, `SELECT `+paymentColumns+paymentFrom+` WHERE pay.id = $1`, payment.ID))
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE payments SET status = $2, provider_reference = NULLIF($3, ''), verified_at = NOW() WHERE id = $1`,
		payment.ID, outcome, v.Reference); err != nil {
		return nil, err
	}
	if outcome == "success" {
		interval := "1 month"
		if payment.BillingCycle == "yearly" {
			interval = "1 year"
		}
		next := models.CompanyActive
		if deps.Config.Billing.RequireApproval {
			next = models.CompanyPendingApproval
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE companies SET
				plan_id = $2, billing_cycle = $3,
				current_period_end = GREATEST(COALESCE(current_period_end, NOW()), NOW()) + $4::interval,
				status = CASE WHEN status IN ('pending_payment', 'expired') THEN $5 ELSE status END,
				updated_at = NOW()
			WHERE id = $1`, payment.CompanyID, payment.PlanID, payment.BillingCycle, interval, next); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	recordAudit(ctx, deps, nil, uuid.Nil, "update", "payment", payment.ID,
		gin.H{"event": "payment_" + outcome, "tx_ref": txRef, "company": payment.CompanyName, "amount": payment.Amount})
	return scanPayment(deps.DB.QueryRowContext(ctx, `SELECT `+paymentColumns+paymentFrom+` WHERE pay.id = $1`, payment.ID))
}

// PaymentStatus reports (and, while pending, verifies) a payment, for the page the customer
// returns to after Chapa's checkout (GET /public/payments/:txRef).
func (h *CompanyHandler) PaymentStatus(c *gin.Context) {
	ctx := c.Request.Context()
	payment, err := settlePayment(ctx, h.deps, c.Param("txRef"))
	if errors.Is(err, errUnknownPayment) {
		c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		return
	}
	if err != nil {
		h.deps.Logger.WithError(err).Warn("Payment verification failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "the payment could not be verified right now; try again in a moment"})
		return
	}
	company, err := loadCompany(ctx, h.deps.DB, payment.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": payment.Status, "amount": payment.Amount, "currency": payment.Currency,
		"company_name": company.Name, "company_status": company.Status,
	})
}

// ChapaCallback is called by Chapa (GET or POST, with trx_ref) when a payment changes.
func (h *CompanyHandler) ChapaCallback(c *gin.Context) {
	txRef := firstNonEmpty(c.Query("trx_ref"), c.Query("tx_ref"), c.PostForm("trx_ref"), c.PostForm("tx_ref"))
	if txRef == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing trx_ref"})
		return
	}
	if _, err := settlePayment(c.Request.Context(), h.deps, txRef); err != nil && !errors.Is(err, errUnknownPayment) {
		h.deps.Logger.WithError(err).Warn("Chapa callback: verification failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "verification failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// ChapaWebhook receives Chapa's signed payment events (POST /public/payments/chapa/webhook).
// The event only triggers a verification with Chapa's API; its content is not trusted.
func (h *CompanyHandler) ChapaWebhook(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if secret := h.deps.Config.Billing.ChapaWebhookSecret; secret != "" &&
		!chapa.ValidSignature(secret, body, c.GetHeader("x-chapa-signature"), c.GetHeader("chapa-signature")) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}
	var event struct {
		TxRef string `json:"tx_ref"`
	}
	if err := json.Unmarshal(body, &event); err != nil || event.TxRef == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tx_ref"})
		return
	}
	if _, err := settlePayment(c.Request.Context(), h.deps, event.TxRef); err != nil && !errors.Is(err, errUnknownPayment) {
		h.deps.Logger.WithError(err).Warn("Chapa webhook: verification failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "verification failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// PublicCheckout lets a company owner pay from the landing page without signing in: to finish
// an interrupted sign-up, or to renew an expired subscription (POST /public/checkout).
func (h *CompanyHandler) PublicCheckout(c *gin.Context) {
	var req struct {
		Email        string `json:"email" binding:"required,email"`
		Password     string `json:"password" binding:"required"`
		PlanCode     string `json:"plan_code"`
		BillingCycle string `json:"billing_cycle" binding:"omitempty,oneof=monthly yearly"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ctx := c.Request.Context()
	auth := &AuthHandler{deps: h.deps}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	emailKey, ipUserKey := "login:fail:email:"+email, "login:fail:ip:"+c.ClientIP()+":"+email
	if retry := auth.loginBlocked(ctx, emailKey, ipUserKey); retry > 0 {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed attempts; try again later"})
		return
	}
	user, err := scanUser(h.deps.DB.QueryRowContext(ctx,
		"SELECT "+userColumns("u")+" FROM users u WHERE u.email = $1 AND u.deleted_at IS NULL", email))
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		if err == nil || errors.Is(err, sql.ErrNoRows) {
			auth.recordLoginFailure(ctx, emailKey, ipUserKey)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
			return
		}
		h.deps.internalError(c, err, "load user")
		return
	}
	if user.CompanyRole != models.CompanyOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the workspace owner can pay for the subscription"})
		return
	}
	company, err := loadCompany(ctx, h.deps.DB, user.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	switch company.Status {
	case models.CompanyPendingPayment, models.CompanyExpired, models.CompanyActive:
	case models.CompanyPendingApproval:
		c.JSON(http.StatusConflict, gin.H{"error": "your workspace is waiting for approval; no payment is needed now"})
		return
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": companyInactiveMessage(company.Status)})
		return
	}
	h.checkout(c, company, user, req.PlanCode, req.BillingCycle)
}

// checkout starts a payment for company (shared by the public and in-app renewal flows).
func (h *CompanyHandler) checkout(c *gin.Context, company *models.Company, payer *models.User, planCode, cycle string) {
	ctx := c.Request.Context()
	if !h.deps.Chapa.Configured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "online payment is not available; contact BinTalk to renew"})
		return
	}
	plan := company.Plan
	if planCode != "" {
		p, err := loadPlanByCode(ctx, h.deps.DB, planCode)
		if errors.Is(err, errNotFound) || (err == nil && !p.IsActive) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown plan"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "load plan")
			return
		}
		plan = p
	}
	if plan == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "choose a plan"})
		return
	}
	if plan.MaxUsers != nil && company.MemberCount > *plan.MaxUsers {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
			"your company has %d members, more than the %s plan allows (%d)", company.MemberCount, plan.Name, *plan.MaxUsers)})
		return
	}
	if cycle == "" {
		cycle = company.BillingCycle
	}
	payment, checkoutURL, err := h.startCheckout(ctx, company, plan, cycle, payer)
	if err != nil {
		h.deps.Logger.WithError(err).Error("Failed to start Chapa checkout")
		c.JSON(http.StatusBadGateway, gin.H{"error": "the payment page could not be opened; try again shortly"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"checkout_url": checkoutURL, "tx_ref": payment.TxRef, "amount": payment.Amount, "currency": payment.Currency})
}

// ---------- the company's own console (owners and admins) ----------

// MyCompany returns the caller's company, plan, seat usage and payments (GET /admin/company).
func (h *CompanyHandler) MyCompany(c *gin.Context) {
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	company, err := loadCompany(ctx, h.deps.DB, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	left, err := seatsLeft(ctx, h.deps.DB, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "count seats")
		return
	}
	payments, err := h.payments(ctx, &a.CompanyID, "", 20)
	if err != nil {
		h.deps.internalError(c, err, "list payments")
		return
	}
	plans, err := listPlans(ctx, h.deps.DB, true)
	if err != nil {
		h.deps.internalError(c, err, "list plans")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"company": company, "seats_left": left, "payments": payments, "plans": plans,
		"online_payment": h.deps.Chapa.Configured(),
	})
}

// RenewCompany starts a payment to renew or change the caller's plan (POST /admin/company/checkout).
func (h *CompanyHandler) RenewCompany(c *gin.Context) {
	var req struct {
		PlanCode     string `json:"plan_code"`
		BillingCycle string `json:"billing_cycle" binding:"omitempty,oneof=monthly yearly"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	company, err := loadCompany(ctx, h.deps.DB, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	payer, err := loadUser(ctx, h.deps.DB, a.ID)
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}
	h.checkout(c, company, payer, req.PlanCode, req.BillingCycle)
}

// ---------- invitations ----------

func invitationStatus(inv *models.Invitation) string {
	switch {
	case inv.AcceptedAt != nil:
		return "accepted"
	case inv.RevokedAt != nil:
		return "revoked"
	case time.Now().After(inv.ExpiresAt):
		return "expired"
	}
	return "pending"
}

// ListInvitations lists the caller's company invitations (GET /admin/invitations).
func (h *CompanyHandler) ListInvitations(c *gin.Context) {
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT i.id, i.email, i.company_role, i.invited_by, i.expires_at, i.accepted_at, i.revoked_at, i.created_at
		FROM invitations i WHERE i.company_id = $1 ORDER BY i.created_at DESC LIMIT 200`, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "list invitations")
		return
	}
	invitations := []models.Invitation{}
	inviters := map[uuid.UUID]bool{}
	var invitedBy []*uuid.UUID
	for rows.Next() {
		var inv models.Invitation
		var by *uuid.UUID
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.CompanyRole, &by, &inv.ExpiresAt, &inv.AcceptedAt,
			&inv.RevokedAt, &inv.CreatedAt); err != nil {
			rows.Close()
			h.deps.internalError(c, err, "scan invitation")
			return
		}
		inv.Status = invitationStatus(&inv)
		if by != nil {
			inviters[*by] = true
		}
		invitations = append(invitations, inv)
		invitedBy = append(invitedBy, by)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list invitations")
		return
	}
	users, err := loadUserDTOs(ctx, h.deps.DB, inviters)
	if err != nil {
		h.deps.internalError(c, err, "load inviters")
		return
	}
	for i, by := range invitedBy {
		if by != nil {
			invitations[i].InvitedBy = users[*by]
		}
	}
	left, err := seatsLeft(ctx, h.deps.DB, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "count seats")
		return
	}
	c.JSON(http.StatusOK, gin.H{"invitations": invitations, "seats_left": left})
}

// CreateInvitation invites someone to the caller's company by email (POST /admin/invitations).
// The link is emailed and also returned, so it can be shared another way.
func (h *CompanyHandler) CreateInvitation(c *gin.Context) {
	var req struct {
		Email       string `json:"email" binding:"required,email,max=255"`
		CompanyRole string `json:"company_role" binding:"omitempty,oneof=admin member"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if req.CompanyRole == "" {
		req.CompanyRole = models.CompanyMember
	}
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	email := strings.ToLower(strings.TrimSpace(req.Email))

	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()
	// Serialize invitations per company so concurrent invites cannot exceed the seat limit.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('invites:' || $1::text))`, a.CompanyID); err != nil {
		h.deps.internalError(c, err, "lock invitations")
		return
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists); err != nil {
		h.deps.internalError(c, err, "check email")
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "this email address already has a BinTalk account"})
		return
	}
	// A new invitation replaces an open one for the same address.
	if _, err := tx.ExecContext(ctx, `
		UPDATE invitations SET revoked_at = NOW()
		WHERE company_id = $1 AND lower(email) = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
		a.CompanyID, email); err != nil {
		h.deps.internalError(c, err, "replace invitation")
		return
	}
	left, err := seatsLeft(ctx, tx, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "count seats")
		return
	}
	if left == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "all seats of your plan are taken (members plus open invitations); upgrade your plan or revoke an invitation"})
		return
	}
	token, err := randomToken()
	if err != nil {
		h.deps.internalError(c, err, "generate invitation")
		return
	}
	var inv models.Invitation
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO invitations (company_id, email, company_role, token_hash, invited_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(secs => $6))
		RETURNING id, email, company_role, expires_at, created_at`,
		a.CompanyID, email, req.CompanyRole, hashToken(token), a.ID, invitationTTL.Seconds(),
	).Scan(&inv.ID, &inv.Email, &inv.CompanyRole, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
		h.deps.internalError(c, err, "create invitation")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "create invitation")
		return
	}
	inv.Status = "pending"

	link := h.deps.Config.Billing.AppBaseURL + "/#invite=" + token
	company, _ := loadCompany(ctx, h.deps.DB, a.CompanyID)
	inviter, _ := loadUser(ctx, h.deps.DB, a.ID)
	companyName, inviterName := "your company", "A colleague"
	if company != nil {
		companyName = company.Name
	}
	if inviter != nil {
		inviterName = firstNonEmpty(inviter.FullName, inviter.Username)
	}
	body := fmt.Sprintf("Hi,\n\n%s invited you to join %s on BinTalk, your team's chat.\n\n"+
		"Create your account with this link (valid for 7 days):\n\n%s\n\n— BinTalk\n", inviterName, companyName, link)
	go func() {
		if err := h.deps.Mailer.Send(email, "You're invited to "+companyName+" on BinTalk", body); err != nil {
			h.deps.Logger.WithError(err).Warn("Failed to send invitation email")
		}
	}()
	recordAudit(ctx, h.deps, c, a.ID, "create", "invitation", inv.ID, gin.H{"email": email, "company_role": req.CompanyRole})
	c.JSON(http.StatusCreated, gin.H{"invitation": inv, "invite_link": link})
}

// RevokeInvitation cancels an open invitation (DELETE /admin/invitations/:id).
func (h *CompanyHandler) RevokeInvitation(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	res, err := h.deps.DB.ExecContext(c.Request.Context(), `
		UPDATE invitations SET revoked_at = NOW()
		WHERE id = $1 AND company_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`, id, a.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "revoke invitation")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no open invitation with that id"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

// InvitationInfo describes an invitation for the sign-up form (GET /public/invitations/:token).
func (h *CompanyHandler) InvitationInfo(c *gin.Context) {
	var email, role, companyName, companyStatus string
	var expires time.Time
	err := h.deps.DB.QueryRowContext(c.Request.Context(), `
		SELECT i.email, i.company_role, i.expires_at, co.name, co.status
		FROM invitations i JOIN companies co ON co.id = i.company_id
		WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW()`,
		hashToken(c.Param("token"))).Scan(&email, &role, &expires, &companyName, &companyStatus)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "this invitation is invalid or has expired; ask your company admin for a new one"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load invitation")
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": email, "company_role": role, "expires_at": expires,
		"company_name": companyName, "company_active": companyStatus == models.CompanyActive})
}

// ---------- platform administration ----------

func (h *CompanyHandler) payments(ctx context.Context, company *uuid.UUID, status string, limit int) ([]models.Payment, error) {
	rows, err := h.deps.DB.QueryContext(ctx, `SELECT `+paymentColumns+paymentFrom+`
		WHERE ($1::uuid IS NULL OR pay.company_id = $1) AND ($2 = '' OR pay.status = $2)
		ORDER BY pay.created_at DESC LIMIT $3`, company, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	payments := []models.Payment{}
	for rows.Next() {
		p, err := scanPayment(rows)
		if err != nil {
			return nil, err
		}
		payments = append(payments, *p)
	}
	return payments, rows.Err()
}

// ListPayments lists payments across companies (GET /platform/payments?status=).
func (h *CompanyHandler) ListPayments(c *gin.Context) {
	limit, _ := paging(c)
	payments, err := h.payments(c.Request.Context(), nil, c.Query("status"), limit)
	if err != nil {
		h.deps.internalError(c, err, "list payments")
		return
	}
	c.JSON(http.StatusOK, gin.H{"payments": payments})
}

// ListCompanies lists companies with their plan and size (GET /platform/companies?status=&q=).
func (h *CompanyHandler) ListCompanies(c *gin.Context) {
	ctx := c.Request.Context()
	q := "%" + escapeLike(strings.TrimSpace(c.Query("q"))) + "%"
	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT `+companyColumns+` FROM companies c
		WHERE ($1 = '' OR c.status = $1) AND (c.name ILIKE $2 OR c.slug ILIKE $2 OR c.contact_email ILIKE $2)
		ORDER BY (c.status = 'pending_approval') DESC, c.created_at DESC LIMIT 200`, c.Query("status"), q)
	if err != nil {
		h.deps.internalError(c, err, "list companies")
		return
	}
	var companies []*models.Company
	for rows.Next() {
		co, err := scanCompany(rows)
		if err != nil {
			rows.Close()
			h.deps.internalError(c, err, "scan company")
			return
		}
		companies = append(companies, co)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list companies")
		return
	}
	out := []*models.Company{}
	for _, co := range companies {
		if err := attachPlan(ctx, h.deps.DB, co); err != nil {
			h.deps.internalError(c, err, "load plan")
			return
		}
		out = append(out, co)
	}
	c.JSON(http.StatusOK, gin.H{"companies": out})
}

// CreateCompany registers an active company and its owner directly (POST /platform/companies).
// The owner gets a temporary password, returned once, which they must change at first sign-in.
func (h *CompanyHandler) CreateCompany(c *gin.Context) {
	var req struct {
		Name          string `json:"name" binding:"required,max=150"`
		Slug          string `json:"slug" binding:"max=60"`
		PlanCode      string `json:"plan_code" binding:"required"`
		BillingCycle  string `json:"billing_cycle" binding:"omitempty,oneof=monthly yearly"`
		PeriodMonths  int    `json:"period_months" binding:"min=0,max=120"` // 0 = no expiry
		OwnerFullName string `json:"owner_full_name" binding:"required"`
		OwnerUsername string `json:"owner_username" binding:"required"`
		OwnerEmail    string `json:"owner_email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if req.BillingCycle == "" {
		req.BillingCycle = "monthly"
	}
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	plan, err := loadPlanByCode(ctx, h.deps.DB, req.PlanCode)
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown plan"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load plan")
		return
	}
	password := generatePassword()
	owner := newAccount{Username: req.OwnerUsername, Email: req.OwnerEmail, FullName: req.OwnerFullName,
		Password: password, CompanyRole: models.CompanyOwner, MustChangePassword: true}
	if msg := validateAccount(&owner); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()
	slug, err := uniqueSlug(ctx, tx, firstNonEmpty(strings.TrimSpace(req.Slug), req.Name))
	if err != nil {
		h.deps.internalError(c, err, "choose slug")
		return
	}
	var periodEnd interface{}
	if req.PeriodMonths > 0 {
		periodEnd = time.Now().UTC().AddDate(0, req.PeriodMonths, 0)
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO companies (name, slug, status, plan_id, billing_cycle, contact_email, current_period_end,
			approved_at, approved_by)
		VALUES ($1, $2, 'active', $3, $4, $5, $6, NOW(), $7) RETURNING id`,
		strings.TrimSpace(req.Name), slug, plan.ID, req.BillingCycle, owner.Email, periodEnd, a.ID,
	).Scan(&owner.CompanyID); err != nil {
		h.deps.internalError(c, err, "create company")
		return
	}
	user, err := createUser(ctx, tx, owner)
	if errors.Is(err, errAccountTaken) {
		c.JSON(http.StatusConflict, gin.H{"error": "that username or email already has a BinTalk account"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "create owner")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "create company")
		return
	}
	company, err := loadCompany(ctx, h.deps.DB, owner.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	recordAudit(ctx, h.deps, c, a.ID, "create", "company", company.ID, gin.H{"event": "company_created", "company": company.Name})
	c.JSON(http.StatusCreated, gin.H{"company": company, "owner": user.ToDTO(), "temporary_password": password})
}

// UpdateCompany approves, suspends, rejects or reactivates a company, changes its plan, or sets
// or extends its paid period (PUT /platform/companies/:id).
func (h *CompanyHandler) UpdateCompany(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Status       string  `json:"status" binding:"omitempty,oneof=active suspended rejected expired"`
		PlanCode     string  `json:"plan_code"`
		BillingCycle string  `json:"billing_cycle" binding:"omitempty,oneof=monthly yearly"`
		ExtendMonths int     `json:"extend_months" binding:"min=0,max=120"`
		PeriodEnd    *string `json:"current_period_end"` // RFC 3339 date-time, or "" for no expiry
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	before, err := loadCompany(ctx, h.deps.DB, id)
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "company not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	var planID *uuid.UUID
	if req.PlanCode != "" {
		plan, err := loadPlanByCode(ctx, h.deps.DB, req.PlanCode)
		if errors.Is(err, errNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown plan"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "load plan")
			return
		}
		planID = &plan.ID
	}
	setPeriod, clearPeriod := false, false
	var periodEnd time.Time
	if req.PeriodEnd != nil {
		if *req.PeriodEnd == "" {
			clearPeriod = true
		} else if periodEnd, err = time.Parse(time.RFC3339, *req.PeriodEnd); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "current_period_end must be an RFC 3339 date-time"})
			return
		} else {
			setPeriod = true
		}
	}

	_, err = h.deps.DB.ExecContext(ctx, `
		UPDATE companies SET
			status = COALESCE(NULLIF($2, ''), status),
			plan_id = COALESCE($3, plan_id),
			billing_cycle = COALESCE(NULLIF($4, ''), billing_cycle),
			current_period_end = CASE
				WHEN $5 THEN NULL
				WHEN $6 THEN $7::timestamp
				WHEN $8 > 0 THEN GREATEST(COALESCE(current_period_end, NOW()), NOW()) + make_interval(months => $8)
				ELSE current_period_end END,
			approved_at = CASE WHEN $2 = 'active' AND approved_at IS NULL THEN NOW() ELSE approved_at END,
			approved_by = CASE WHEN $2 = 'active' AND approved_by IS NULL THEN $9 ELSE approved_by END,
			updated_at = NOW()
		WHERE id = $1`,
		id, req.Status, planID, req.BillingCycle, clearPeriod, setPeriod, periodEnd, req.ExtendMonths, a.ID)
	if err != nil {
		h.deps.internalError(c, err, "update company")
		return
	}
	company, err := loadCompany(ctx, h.deps.DB, id)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	if before.IsActive() && !company.IsActive() {
		endCompanySessions(ctx, h.deps, id)
	}
	recordAudit(ctx, h.deps, c, a.ID, "update", "company", id, gin.H{
		"company": company.Name, "status": gin.H{"from": before.Status, "to": company.Status},
		"plan": req.PlanCode, "extend_months": req.ExtendMonths,
	})
	c.JSON(http.StatusOK, gin.H{"company": company})
}

// PlatformPlans lists every plan, including retired ones (GET /platform/plans).
func (h *CompanyHandler) PlatformPlans(c *gin.Context) {
	plans, err := listPlans(c.Request.Context(), h.deps.DB, false)
	if err != nil {
		h.deps.internalError(c, err, "list plans")
		return
	}
	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

type planRequest struct {
	Code         string   `json:"code"`
	Name         string   `json:"name" binding:"max=100"`
	Description  *string  `json:"description" binding:"omitempty,max=500"`
	MaxUsers     *int     `json:"max_users" binding:"omitempty,min=0"` // 0 = unlimited
	PriceMonthly *float64 `json:"price_monthly" binding:"omitempty,min=0"`
	PriceYearly  *float64 `json:"price_yearly" binding:"omitempty,min=0"`
	IsActive     *bool    `json:"is_active"`
	SortOrder    *int     `json:"sort_order"`
}

func validPrice(p *float64) bool {
	return p == nil || (!math.IsNaN(*p) && !math.IsInf(*p, 0) && *p < 1e9)
}

// CreatePlan adds a plan (POST /platform/plans).
func (h *CompanyHandler) CreatePlan(c *gin.Context) {
	var req planRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if !planCodeRule.MatchString(req.Code) || strings.TrimSpace(req.Name) == "" ||
		req.PriceMonthly == nil || req.PriceYearly == nil || !validPrice(req.PriceMonthly) || !validPrice(req.PriceYearly) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code (lowercase letters, digits, - or _), name, price_monthly and price_yearly are required"})
		return
	}
	var maxUsers interface{}
	if req.MaxUsers != nil && *req.MaxUsers > 0 {
		maxUsers = *req.MaxUsers
	}
	description := ""
	if req.Description != nil {
		description = strings.TrimSpace(*req.Description)
	}
	plan, err := scanPlan(h.deps.DB.QueryRowContext(c.Request.Context(), `
		INSERT INTO plans AS p (code, name, description, max_users, price_monthly, price_yearly, sort_order)
		VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, 0))
		RETURNING `+planColumns,
		req.Code, strings.TrimSpace(req.Name), description, maxUsers, *req.PriceMonthly, *req.PriceYearly, req.SortOrder))
	if isUniqueViolation(err) {
		c.JSON(http.StatusConflict, gin.H{"error": "a plan with this code exists"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "create plan")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"plan": plan})
}

// UpdatePlan changes a plan (PUT /platform/plans/:id). Prices apply to new payments only.
func (h *CompanyHandler) UpdatePlan(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req planRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if !validPrice(req.PriceMonthly) || !validPrice(req.PriceYearly) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid price"})
		return
	}
	setMax, maxUsers := req.MaxUsers != nil, interface{}(nil)
	if req.MaxUsers != nil && *req.MaxUsers > 0 {
		maxUsers = *req.MaxUsers
	}
	plan, err := scanPlan(h.deps.DB.QueryRowContext(c.Request.Context(), `
		UPDATE plans AS p SET
			name = COALESCE(NULLIF($2, ''), p.name),
			description = COALESCE($3, p.description),
			max_users = CASE WHEN $4 THEN $5::int ELSE p.max_users END,
			price_monthly = COALESCE($6, p.price_monthly),
			price_yearly = COALESCE($7, p.price_yearly),
			is_active = COALESCE($8, p.is_active),
			sort_order = COALESCE($9, p.sort_order),
			updated_at = NOW()
		WHERE p.id = $1
		RETURNING `+planColumns,
		id, strings.TrimSpace(req.Name), req.Description, setMax, maxUsers, req.PriceMonthly, req.PriceYearly,
		req.IsActive, req.SortOrder))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "plan not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "update plan")
		return
	}
	c.JSON(http.StatusOK, gin.H{"plan": plan})
}

// expireCompanies marks companies whose paid period (plus the grace period) has ended as
// expired, and signs their members out. Run by RunMaintenance.
func expireCompanies(ctx context.Context, deps *Dependencies) {
	rows, err := deps.DB.QueryContext(ctx, `
		UPDATE companies SET status = 'expired', updated_at = NOW()
		WHERE status = 'active' AND current_period_end IS NOT NULL
		  AND current_period_end < NOW() - make_interval(secs => $1)
		RETURNING id, name`, deps.Config.Billing.GracePeriod.Seconds())
	if err != nil {
		if ctx.Err() == nil {
			deps.Logger.WithError(err).Warn("Failed to expire companies")
		}
		return
	}
	var expired []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var name string
		if rows.Scan(&id, &name) == nil {
			expired = append(expired, id)
			deps.Logger.Infof("Subscription of company %q expired", name)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		deps.Logger.WithError(err).Warn("Failed to expire companies")
	}
	for _, id := range expired {
		endCompanySessions(ctx, deps, id)
	}
}
