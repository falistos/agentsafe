use axum::Router;

use super::AppState;

/// The web UI's routes, merged into the app behind the same authorization. Empty for now: every
/// path outside the API answers 404.
pub fn router() -> Router<AppState> {
    Router::new()
}
