use serde::{Deserialize, Serialize};

/// User context extracted from session token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: i32,
    pub email: String,
    pub display_name: String,
    pub session_token: String,
    /// Auth0 subject (`auth.users.auth0_id`) of the session's user. The identity
    /// user-scoped playbooks act as; see `crate::identity`. `None` for sessions
    /// cached before this field existed and in dev auth-bypass.
    #[serde(default)]
    pub auth0_sub: Option<String>,
    /// Role names (`auth.user_roles`) of the session's user. Decides which
    /// routes the session may reach; see `crate::authorization`.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Set only for a guest session (`crate::guest`): no user, no subject, no
    /// roles; may start only the guest playbooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<crate::guest::Guest>,
}
