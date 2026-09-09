use crate::http::error::Error;
use axum::body::Body;
use axum::extract::{Extension, FromRequest, RequestParts};

use crate::http::ApiContext;
use async_trait::async_trait;
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderValue;
use hmac::{Hmac, NewMac};
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha384;
use time::OffsetDateTime;
use uuid::Uuid;

const DEFAULT_SESSION_LENGTH: time::Duration = time::Duration::weeks(2);

// A short grace period applied after a token's `exp` claim has passed. Rather than rejecting
// a token the instant it expires, we continue to accept it for a little while longer to avoid
// forcing the client into an immediate hard-cutoff re-authentication (e.g. due to clock skew
// or a request that was already in flight when the token expired).
const GRACE_PERIOD_SECONDS: i64 = 300;

// Ideally the Realworld spec would use the `Bearer` scheme as that's relatively standard
// and has parsers available, but it's really not that hard to parse anyway.
const SCHEME_PREFIX: &str = "Token ";

/// Add this as a parameter to a handler function to require the user to be logged in.
///
/// Parses a JWT from the `Authorization: Token <token>` header.
pub struct AuthUser {
    pub user_id: Uuid,
}

/// Add this as a parameter to a handler function to optionally check if the user is logged in.
///
/// If the `Authorization` header is absent then this will be `Self(None)`, otherwise it will
/// validate the token.
///
/// This is in contrast to directly using `Option<AuthUser>`, which will be `None` if there
/// is *any* error in deserializing, which isn't exactly what we want.
pub struct MaybeAuthUser(pub Option<AuthUser>);

#[derive(serde::Serialize, serde::Deserialize)]
struct AuthUserClaims {
    user_id: Uuid,
    /// Standard JWT `exp` claim.
    exp: i64,
}

impl AuthUser {
    pub(in crate::http) fn to_jwt(&self, ctx: &ApiContext) -> String {
        let hmac = Hmac::<Sha384>::new_from_slice(ctx.config.hmac_key.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");

        AuthUserClaims {
            user_id: self.user_id,
            exp: (OffsetDateTime::now_utc() + DEFAULT_SESSION_LENGTH).unix_timestamp(),
        }
        .sign_with_key(&hmac)
        .expect("HMAC signing should be infallible")
    }

    /// Attempt to parse `Self` from an `Authorization` header.
    fn from_authorization(ctx: &ApiContext, auth_header: &HeaderValue) -> Result<Self, Error> {
        let auth_header = auth_header.to_str().map_err(|_| {
            log::debug!("Authorization header is not UTF-8");
            Error::Unauthorized
        })?;

        if !auth_header.starts_with(SCHEME_PREFIX) {
            log::debug!(
                "Authorization header is using the wrong scheme: {:?}",
                auth_header
            );
            return Err(Error::Unauthorized);
        }

        let token = &auth_header[SCHEME_PREFIX.len()..];

        let jwt =
            jwt::Token::<jwt::Header, AuthUserClaims, _>::parse_unverified(token).map_err(|e| {
                log::debug!(
                    "failed to parse Authorization header {:?}: {}",
                    auth_header,
                    e
                );
                Error::Unauthorized
            })?;

        // Realworld doesn't specify the signing algorithm for use with the JWT tokens
        // so we picked SHA-384 (HS-384) as the HMAC, as it is more difficult to brute-force
        // than SHA-256 (recommended by the JWT spec) at the cost of a slightly larger token.
        let hmac = Hmac::<Sha384>::new_from_slice(ctx.config.hmac_key.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");

        // When choosing a JWT implementation, be sure to check that it validates that the signing
        // algorithm declared in the token matches the signing algorithm you're verifying with.
        // The `jwt` crate does.
        let jwt = jwt.verify_with_key(&hmac).map_err(|e| {
            log::debug!("JWT failed to verify: {}", e);
            Error::Unauthorized
        })?;

        let (_header, claims) = jwt.into();

        // Because JWTs are stateless, we don't really have any mechanism here to invalidate them
        // besides expiration. You probably want to add more checks, like ensuring the user ID
        // exists and has not been deleted/banned/deactivated.
        //
        // You could also use the user's password hash as part of the keying material for the HMAC,
        // so changing their password invalidates their existing sessions.
        //
        // In practice, Launchbadge has abandoned using JWTs for authenticating long-lived sessions,
        // instead storing session data in Redis, which can be accessed quickly and so adds less
        // overhead to every request compared to hitting Postgres, and allows tracking and
        // invalidating individual sessions by simply deleting them from Redis.
        //
        // Technically, the Realworld spec isn't all that adamant about using JWTs and there
        // may be some flexibility in using other kinds of tokens, depending on whether the frontend
        // is expected to parse the token or just treat it as an opaque string.
        //
        // Also, if the consumer of your API is a browser, you probably want to put your session
        // token in a cookie instead of the response body. By setting the `HttpOnly` flag, the cookie
        // isn't exposed in the response to Javascript at all which, along with setting `Domain` and
        // `SameSite`, prevents all kinds of session hijacking exploits.
        //
        // This also has the benefit of avoiding having to deal with securely storing the session
        // token on the frontend.

        if claims.exp + GRACE_PERIOD_SECONDS < OffsetDateTime::now_utc().unix_timestamp() {
            log::debug!("token expired");
            return Err(Error::Unauthorized);
        }

        Ok(Self {
            user_id: claims.user_id,
        })
    }
}

impl MaybeAuthUser {
    /// If this is `Self(Some(AuthUser))`, return `AuthUser::user_id`
    pub fn user_id(&self) -> Option<Uuid> {
        self.0.as_ref().map(|auth_user| auth_user.user_id)
    }
}

// tower-http has a `RequireAuthorizationLayer` but it's useless for practical applications,
// as it only supports matching Basic or Bearer auth with credentials you provide it.
//
// There's the `::custom()` constructor to provide your own validator but it basically
// requires parsing the `Authorization` header by-hand anyway so you really don't get anything
// out of it that you couldn't write your own middleware for, except with a bunch of extra
// boilerplate.
#[async_trait]
impl FromRequest for AuthUser {
    type Rejection = Error;

    async fn from_request(req: &mut RequestParts<Body>) -> Result<Self, Self::Rejection> {
        let ctx: Extension<ApiContext> = Extension::from_request(req)
            .await
            .expect("BUG: ApiContext was not added as an extension");

        // Get the value of the `Authorization` header, if it was sent at all.
        let auth_header = req
            .headers()
            .ok_or(Error::Unauthorized)?
            .get(AUTHORIZATION)
            .ok_or(Error::Unauthorized)?;

        Self::from_authorization(&ctx, auth_header)
    }
}

#[async_trait]
impl FromRequest for MaybeAuthUser {
    type Rejection = Error;

    async fn from_request(req: &mut RequestParts<Body>) -> Result<Self, Self::Rejection> {
        let ctx: Extension<ApiContext> = Extension::from_request(req)
            .await
            .expect("BUG: ApiContext was not added as an extension");

        Ok(Self(
            // Get the value of the `Authorization` header, if it was sent at all.
            req.headers()
                .and_then(|headers| {
                    let auth_header = headers.get(AUTHORIZATION)?;
                    Some(AuthUser::from_authorization(&ctx, auth_header))
                })
                .transpose()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::http::HeaderValue;
    use hmac::{Hmac, NewMac};
    use jwt::SignWithKey;
    use sha2::Sha384;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    const TEST_HMAC_KEY: &str = "test-hmac-key-for-unit-tests";

    /// Build an `ApiContext` suitable for unit tests that never touch the database.
    ///
    /// `AuthUser::from_authorization` only ever reads `ctx.config.hmac_key`, so we can safely
    /// hand it a lazily-connected `PgPool` here: `connect_lazy` never opens a real connection
    /// until a query is actually run against the pool, which these tests never do. This avoids
    /// requiring a live Postgres instance to run this test suite.
    ///
    /// Two `sqlx` 0.5.9 quirks around `connect_lazy` had to be worked around here (neither
    /// involves actually reaching a database, both are just about satisfying `sqlx`'s internal
    /// bookkeeping):
    ///
    /// - `PgPoolOptions::new()` defaults to non-`None` `idle_timeout`/`max_lifetime`, which
    ///   would make the pool spawn a background "reaper" task. Disabled below, though it turns
    ///   out not to be the whole story (see next point).
    /// - Regardless of the above, `connect_lazy`/`connect_lazy_with` *unconditionally* spawns a
    ///   task via `tokio::spawn` to opportunistically open the pool's minimum connections in the
    ///   background; it does not block on it, but scheduling it still requires an ambient Tokio
    ///   runtime context, which a plain synchronous `#[test]` does not have on its own
    ///   (`tokio::spawn` panics with "there is no reactor running" otherwise). We build a
    ///   throwaway runtime and `enter()` it (without `block_on`-ing anything) just so
    ///   `connect_lazy` has somewhere to schedule that task; the task itself will fail to reach
    ///   the fake host, which is irrelevant since these tests never issue a real query.
    fn test_ctx() -> ApiContext {
        let rt = tokio::runtime::Runtime::new().expect("failed to build a throwaway Tokio runtime");
        let _guard = rt.enter();

        let db = PgPoolOptions::new()
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_lazy("postgres://user:pass@localhost/db")
            .expect("connect_lazy should not require a reachable database");

        let config = Config {
            database_url: "postgres://user:pass@localhost/db".into(),
            hmac_key: TEST_HMAC_KEY.into(),
        };

        ApiContext {
            config: Arc::new(config),
            db,
        }
    }

    /// Build a raw `Authorization` header value for a hand-crafted JWT with the given `exp`,
    /// signed with the same HMAC-SHA-384 scheme that `from_authorization` verifies against.
    fn auth_header_with_exp(exp: i64) -> HeaderValue {
        let hmac = Hmac::<Sha384>::new_from_slice(TEST_HMAC_KEY.as_bytes())
            .expect("HMAC-SHA-384 can accept any key length");

        let claims = AuthUserClaims {
            // `uuid::Uuid::new_v4` requires the crate's "v4" feature, which this project does
            // not enable (see Cargo.toml), so we build a fixed, valid `Uuid` by hand instead.
            user_id: Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0),
            exp,
        };

        let token = claims
            .sign_with_key(&hmac)
            .expect("HMAC signing should be infallible");

        HeaderValue::from_str(&format!("{}{}", SCHEME_PREFIX, token))
            .expect("token should be a valid header value")
    }

    #[test]
    fn token_with_future_exp_is_accepted() {
        let ctx = test_ctx();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let header = auth_header_with_exp(now + DEFAULT_SESSION_LENGTH.whole_seconds());

        assert!(AuthUser::from_authorization(&ctx, &header).is_ok());
    }

    #[test]
    fn token_within_grace_period_after_exp_is_accepted() {
        let ctx = test_ctx();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        // Expired 60 seconds ago, well within the 300 second grace period.
        let header = auth_header_with_exp(now - 60);

        assert!(AuthUser::from_authorization(&ctx, &header).is_ok());
    }

    #[test]
    fn token_well_past_grace_period_is_rejected() {
        let ctx = test_ctx();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        // Expired 600 seconds ago, well past the 300 second grace period.
        let header = auth_header_with_exp(now - 600);

        assert!(AuthUser::from_authorization(&ctx, &header).is_err());
    }
}
