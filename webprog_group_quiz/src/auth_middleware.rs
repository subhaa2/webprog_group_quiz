use actix_web::{dev::ServiceResponse, dev::ServiceRequest, Error, HttpMessage, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web::body::EitherBody;
use actix_web::body::BoxBody;
use actix_session::SessionExt;
use futures_util::future::{ok, Either, Ready, ready};
use serde_json;

/// Middleware function to check session-based authentication
pub fn session_validator(req: ServiceRequest) -> Ready<Result<ServiceRequest, (Error, ServiceRequest)>> {
    let session = req.get_session();

    if let Ok(Some(_username)) = session.get::<String>("username") {
        ready(Ok(req))  // user is authenticated
    } else {
        let err = actix_web::error::ErrorUnauthorized("Not logged in");
        ready(Err((err, req)))
    }
}