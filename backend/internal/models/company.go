package models

import (
	"time"

	"github.com/google/uuid"
)

// Company statuses. Only active companies can sign in.
const (
	CompanyPendingPayment  = "pending_payment"
	CompanyPendingApproval = "pending_approval"
	CompanyActive          = "active"
	CompanySuspended       = "suspended"
	CompanyExpired         = "expired"
	CompanyRejected        = "rejected"
)

// Company roles. Owners and admins manage their company's members, invitations and billing.
const (
	CompanyOwner  = "owner"
	CompanyAdmin  = "admin"
	CompanyMember = "member"
)

// Plan is a subscription plan with a seat limit.
type Plan struct {
	ID           uuid.UUID `json:"id"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	MaxUsers     *int      `json:"max_users"` // nil = unlimited
	PriceMonthly float64   `json:"price_monthly"`
	PriceYearly  float64   `json:"price_yearly"`
	Currency     string    `json:"currency"`
	IsActive     bool      `json:"is_active"`
	SortOrder    int       `json:"sort_order"`
}

// Price returns the plan's price for a billing cycle (monthly or yearly).
func (p *Plan) Price(cycle string) float64 {
	if cycle == "yearly" {
		return p.PriceYearly
	}
	return p.PriceMonthly
}

// Company is a subscribed organization. People can only communicate within their company.
type Company struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Slug             string     `json:"slug"`
	Status           string     `json:"status"`
	PlanID           *uuid.UUID `json:"plan_id,omitempty"`
	BillingCycle     string     `json:"billing_cycle"`
	ContactEmail     string     `json:"contact_email"`
	ContactPhone     string     `json:"contact_phone,omitempty"`
	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`

	Plan        *Plan `json:"plan,omitempty"`
	MemberCount int   `json:"member_count"`
}

// IsActive reports whether the company's members may use BinTalk.
func (c *Company) IsActive() bool {
	return c.Status == CompanyActive
}

// Payment is one checkout for a company's subscription.
type Payment struct {
	ID                uuid.UUID  `json:"id"`
	CompanyID         uuid.UUID  `json:"company_id"`
	CompanyName       string     `json:"company_name,omitempty"`
	PlanID            uuid.UUID  `json:"plan_id"`
	PlanName          string     `json:"plan_name,omitempty"`
	BillingCycle      string     `json:"billing_cycle"`
	TxRef             string     `json:"tx_ref"`
	Amount            float64    `json:"amount"`
	Currency          string     `json:"currency"`
	Status            string     `json:"status"`
	Provider          string     `json:"provider"`
	ProviderReference string     `json:"provider_reference,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
}

// Invitation lets one email address join a company.
type Invitation struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	CompanyRole string     `json:"company_role"`
	InvitedBy   *UserDTO   `json:"invited_by,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Status      string     `json:"status"` // pending | accepted | revoked | expired
}
