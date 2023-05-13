use crate::routes::ServerError;
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};

use actix_web::{
    body::EitherBody,
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};

use ipnet::IpNet;
use std::net::IpAddr;

pub struct ExportAuthentification;

impl<S, B> Transform<S, ServiceRequest> for ExportAuthentification
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = ExportAuthentificationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let raw_address_ranges: Vec<String> = serde_json::from_str(
            &std::env::var("DATACARE_PROMETHEUS_ALLOWED_IPS")
                .expect("No Ip ranges for prometheus configured."),
        )
        .expect("DATACARE_PROMETHEUS_ALLOWED_IPS is not a valid json list.");
        let allowed_ranges: Vec<IpNet> = raw_address_ranges
            .iter()
            .map(|x| x.parse().expect("Ip Range has not valid format."))
            .collect();

        ready(Ok(ExportAuthentificationMiddleware {
            service,
            allowed_ranges,
        }))
    }
}
pub struct ExportAuthentificationMiddleware<S> {
    service: S,
    allowed_ranges: Vec<IpNet>,
}

impl<S, B> Service<ServiceRequest> for ExportAuthentificationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        if request.path().contains("/metrics") {
            if let Some(source_ip_address) = request.request().peer_addr() {
                let parsed_addr: IpAddr = source_ip_address.ip();
                for address_range in &self.allowed_ranges {
                    if address_range.contains(&parsed_addr) {
                        let res = self.service.call(request);
                        return Box::pin(async move {
                            res.await.map(ServiceResponse::map_into_left_body)
                        });
                    }
                }
            }

            return Box::pin(async { Err(ServerError::Forbidden.into()) });
        }
        let res = self.service.call(request);

        Box::pin(async move { res.await.map(ServiceResponse::map_into_left_body) })
    }
}
