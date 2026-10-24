//! Contract error codes for /auth/* endpoints (design §5.5).
use axum::{Json, http::{HeaderValue, StatusCode, header}, response::{IntoResponse, Response}};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct AuthError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}
impl AuthError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), details: None }
    }
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthenticated", message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    pub fn auth_disabled() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "auth_disabled", "auth is disabled")
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
    pub fn missing() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }
    pub fn provider_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "provider_unavailable", message)
    }
    pub fn state_invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "state_invalid", message)
    }
    pub fn grant_invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "grant_invalid", message)
    }
    pub fn redirect_not_allowed() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "redirect_not_allowed", "redirect must be a same-origin relative path")
    }
    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many requests")
    }
    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message.to_string())
    }
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let mut error = json!({"code": self.code, "message": self.message});
        if let Some(d) = self.details {
            error["details"] = d;
        }
        let mut response = (self.status, Json(json!({"error": error}))).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
impl From<rusqlite::Error> for AuthError {
    fn from(e: rusqlite::Error) -> Self {
        AuthError::internal(e)
    }
}
