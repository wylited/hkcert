use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::{Request, StatusCode};

/// Custom extractor for handling both JSON and plain text
pub enum LogBody {
    Json(serde_json::Value),
    Text(String),
}

impl LogBody {
    /// Get the content as a string
    pub fn as_string(&self) -> String {
        match self {
            LogBody::Json(v) => v.to_string(),
            LogBody::Text(s) => s.clone(),
        }
    }

    /// Try to parse as JSON
    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            LogBody::Json(v) => Some(v),
            LogBody::Text(s) => serde_json::from_str(s).ok(),
        }
    }
}

#[axum::async_trait]
impl<S> FromRequest<S> for LogBody
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json");

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to read body: {}", e)))?;

        let body = String::from_utf8(bytes.to_vec())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid UTF-8".to_string()))?;

        if content_type.starts_with("application/json") {
            match serde_json::from_str(&body) {
                Ok(json) => Ok(LogBody::Json(json)),
                Err(_) => Ok(LogBody::Text(body)),
            }
        } else {
            Ok(LogBody::Text(body))
        }
    }
}
