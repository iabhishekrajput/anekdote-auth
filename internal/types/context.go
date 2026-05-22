package types

type ContextKey string

const (
	UserContextKey      ContextKey = "user_id"
	IsAdminContextKey   ContextKey = "is_admin"
	AdminRoleContextKey ContextKey = "admin_role"
)
