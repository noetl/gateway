pub mod schema;
pub mod types;

use axum::Extension;

use crate::auth::types::UserContext;
use schema::AppSchema;

/// POST /graphql. Runs the schema with the caller the auth middleware verified,
/// so resolvers can bind identity variables to it (`crate::identity`).
///
/// This replaces mounting `async_graphql_axum::GraphQL` as a bare service, which
/// does not carry request extensions into the schema: resolvers could not see
/// who was calling at all.
pub async fn graphql_handler(
    Extension(schema): Extension<AppSchema>,
    user: Option<Extension<UserContext>>,
    req: async_graphql_axum::GraphQLRequest,
) -> async_graphql_axum::GraphQLResponse {
    let mut req = req.into_inner();
    if let Some(Extension(user)) = user {
        req = req.data(user);
    }
    schema.execute(req).await.into()
}
