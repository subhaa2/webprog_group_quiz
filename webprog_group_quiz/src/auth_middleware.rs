use actix_web::{dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::auth::validate_jwt;

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let token = credentials.token();
    match validate_jwt(token) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Err(_) => {
            // Return a JSON error message
            let err = actix_web::error::InternalError::from_response(
                "",
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid or missing token"
                }))
            ).into();
            Err((err, req))
        }
    }
}