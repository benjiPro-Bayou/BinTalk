package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

// Every user belongs to one company, and may only see and talk to people in it. Platform admins
// (users.role = 'admin') run the service: they manage companies, plans and payments. Company
// owners and admins (users.company_role) manage their own company's members and billing.

const actorKey = "actor"

// actor is the signed-in user's identity within their company.
type actor struct {
	ID          uuid.UUID
	CompanyID   uuid.UUID
	CompanyRole string
	Role        string
}

// IsPlatformAdmin reports whether the actor administers the whole service.
func (a actor) IsPlatformAdmin() bool { return a.Role == "admin" }

// IsCompanyAdmin reports whether the actor manages their company (owner or admin).
func (a actor) IsCompanyAdmin() bool {
	return a.CompanyRole == models.CompanyOwner || a.CompanyRole == models.CompanyAdmin
}

// currentActor loads the caller's company and roles (once per request). On failure it writes a
// response and returns false.
func currentActor(c *gin.Context, deps *Dependencies) (actor, bool) {
	if v, ok := c.Get(actorKey); ok {
		return v.(actor), true
	}
	a := actor{ID: middleware.GetUserID(c)}
	err := deps.DB.QueryRowContext(c.Request.Context(), `
		SELECT company_id, company_role, COALESCE(role, 'user') FROM users WHERE id = $1`, a.ID,
	).Scan(&a.CompanyID, &a.CompanyRole, &a.Role)
	if errors.Is(err, sql.ErrNoRows) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return actor{}, false
	}
	if err != nil {
		deps.internalError(c, err, "load caller")
		return actor{}, false
	}
	c.Set(actorKey, a)
	return a, true
}

// RequireCompanyAdmin allows company owners and admins, and platform admins. Use after
// middleware.AuthMiddleware.
func RequireCompanyAdmin(deps *Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		a, ok := currentActor(c, deps)
		if !ok {
			return
		}
		if !a.IsCompanyAdmin() && !a.IsPlatformAdmin() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "only company admins can do this"})
			return
		}
		c.Next()
	}
}

// loadColleague loads a user in the given company. Users of other companies are reported as
// not found, so their existence is not revealed.
func loadColleague(ctx context.Context, db *sql.DB, companyID, userID uuid.UUID) (*models.User, error) {
	u, err := loadUser(ctx, db, userID)
	if err != nil {
		return nil, err
	}
	if u.CompanyID != companyID {
		return nil, errNotFound
	}
	return u, nil
}

const companyColumns = `c.id, c.name, c.slug, c.status, c.plan_id, c.billing_cycle, c.contact_email,
	COALESCE(c.contact_phone, ''), c.current_period_end, c.approved_at, c.created_at`

func scanCompany(row rowScanner, extra ...interface{}) (*models.Company, error) {
	var co models.Company
	dest := []interface{}{&co.ID, &co.Name, &co.Slug, &co.Status, &co.PlanID, &co.BillingCycle,
		&co.ContactEmail, &co.ContactPhone, &co.CurrentPeriodEnd, &co.ApprovedAt, &co.CreatedAt}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	return &co, nil
}

// loadCompany loads a company with its plan and member count.
func loadCompany(ctx context.Context, q queryer, id uuid.UUID) (*models.Company, error) {
	co, err := scanCompany(q.QueryRowContext(ctx, `SELECT `+companyColumns+` FROM companies c WHERE c.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return co, attachPlan(ctx, q, co)
}

// attachPlan fills in a company's plan and member count.
func attachPlan(ctx context.Context, q queryer, co *models.Company) error {
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE company_id = $1 AND deleted_at IS NULL`, co.ID).Scan(&co.MemberCount); err != nil {
		return err
	}
	if co.PlanID == nil {
		return nil
	}
	plan, err := scanPlan(q.QueryRowContext(ctx, `SELECT `+planColumns+` FROM plans p WHERE p.id = $1`, *co.PlanID))
	if err == nil {
		co.Plan = plan
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

const planColumns = `p.id, p.code, p.name, p.description, p.max_users, p.price_monthly::float8,
	p.price_yearly::float8, p.currency, p.is_active, p.sort_order`

func scanPlan(row rowScanner) (*models.Plan, error) {
	var p models.Plan
	if err := row.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &p.MaxUsers, &p.PriceMonthly,
		&p.PriceYearly, &p.Currency, &p.IsActive, &p.SortOrder); err != nil {
		return nil, err
	}
	return &p, nil
}

// seatsLeft reports how many more people can join a company under its plan (-1 = unlimited),
// counting members and open invitations.
func seatsLeft(ctx context.Context, q queryer, companyID uuid.UUID) (int, error) {
	var maxUsers *int
	var members, invites int
	err := q.QueryRowContext(ctx, `
		SELECT p.max_users,
			(SELECT COUNT(*) FROM users u WHERE u.company_id = c.id AND u.deleted_at IS NULL),
			(SELECT COUNT(*) FROM invitations i WHERE i.company_id = c.id
			   AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW())
		FROM companies c LEFT JOIN plans p ON p.id = c.plan_id
		WHERE c.id = $1`, companyID).Scan(&maxUsers, &members, &invites)
	if err != nil {
		return 0, err
	}
	if maxUsers == nil {
		return -1, nil
	}
	if left := *maxUsers - members - invites; left > 0 {
		return left, nil
	}
	return 0, nil
}

// endCompanySessions signs out every member of a company (when it is suspended, rejected or its
// subscription expires). Platform admins keep their sessions.
func endCompanySessions(ctx context.Context, deps *Dependencies, companyID uuid.UUID) {
	rows, err := deps.DB.QueryContext(ctx, `
		UPDATE users SET session_generation = session_generation + 1
		WHERE company_id = $1 AND COALESCE(role, 'user') <> 'admin'
		RETURNING id, session_generation`, companyID)
	if err != nil {
		deps.Logger.WithError(err).Error("Failed to end company sessions")
		return
	}
	type gen struct {
		id  uuid.UUID
		gen int64
	}
	var users []gen
	for rows.Next() {
		var g gen
		if err := rows.Scan(&g.id, &g.gen); err == nil {
			users = append(users, g)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		deps.Logger.WithError(err).Error("Failed to end company sessions")
	}
	for _, u := range users {
		deps.Hub().SendToUsers([]uuid.UUID{u.id}, "account.company_inactive", gin.H{})
		if err := revokeSessions(ctx, deps, u.id, u.gen); err != nil {
			deps.Logger.WithError(err).Warn("Failed to revoke a session of an inactive company")
		}
	}
}

// companyInactiveMessage explains to a member why they cannot sign in.
func companyInactiveMessage(status string) string {
	switch status {
	case models.CompanyPendingPayment:
		return "Your company's subscription payment has not been completed yet."
	case models.CompanyPendingApproval:
		return "Your company's workspace is waiting for approval. You will be able to sign in once it is approved."
	case models.CompanyExpired:
		return "Your company's subscription has expired. The workspace owner can renew it from the BinTalk home page."
	case models.CompanyRejected:
		return "Your company's registration was not approved. Contact BinTalk support."
	default:
		return "Your company's workspace is suspended. Contact your workspace owner."
	}
}
