// Copyright 2019 Walmart Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod error;
mod routes;

use std::sync::mpsc;
use std::thread;

use actix_web::{
    client::Client, error as ActixError, web, App, FromRequest, HttpResponse, HttpServer, Result,
};
use futures::future::Future;
use splinter::node_registry::Node;

pub use error::{RestApiResponseError, RestApiServerError};
use routes::ErrorResponse;

#[derive(Clone)]
pub struct ConsortiumData {
    pub public_key: String,
}

pub struct RestApiShutdownHandle {
    do_shutdown: Box<dyn Fn() -> Result<(), RestApiServerError> + Send>,
}

impl RestApiShutdownHandle {
    pub fn shutdown(&self) -> Result<(), RestApiServerError> {
        (*self.do_shutdown)()
    }
}

pub fn run(
    bind_url: &str,
    splinterd_url: &str,
    node: Node,
    public_key: String,
) -> Result<
    (
        RestApiShutdownHandle,
        thread::JoinHandle<Result<(), RestApiServerError>>,
    ),
    RestApiServerError,
> {
    let bind_url = bind_url.to_owned();
    let splinterd_url = splinterd_url.to_owned();
    let consortium_data = ConsortiumData { public_key };
    let (tx, rx) = mpsc::channel();
    let join_handle = thread::Builder::new()
        .name("AdminDaemonService".into())
        .spawn(move || {
            let sys = actix::System::new("DaemonService-REST-API");

            let addr = HttpServer::new(move || {
                App::new()
                    .data(Client::new())
                    .data(splinterd_url.to_owned())
                    .data(node.clone())
                    .data(consortium_data.clone())
                    .data(
                        // change path extractor configuration
                        web::Path::<String>::configure(|cfg| {
                            // <- create custom error response
                            cfg.error_handler(|err, _| handle_error(Box::new(err)))
                        }),
                    )
                    .data(
                        // change json extractor configuration
                        web::Json::<String>::configure(|cfg| {
                            // <- create custom error response
                            cfg.error_handler(|err, _| handle_error(Box::new(err)))
                        }),
                    )
                    .service(
                        web::resource("/nodes/{identity}")
                            .route(web::get().to_async(routes::fetch_node)),
                    )
                    .service(web::resource("/nodes").route(web::get().to_async(routes::list_nodes)))
                    .service(
                        web::resource("/circuits/propose")
                            .route(web::post().to_async(routes::propose_consortium)),
                    )
                    .service(
                        web::scope("/proposals")
                            .service(
                                web::resource("/{proposal_id}/vote")
                                    .route(web::post().to_async(routes::proposal_vote)),
                            )
                        )
                        .service(
                            web::resource("/submit")
                                .route(web::post().to_async(routes::submit_signed_payload)),
                        )
                        .service(
                            web::scope("/circuits")
                                .service(
                                    web::scope("/{circuit_id}")
                                    .service(web::resource("/batches").route(
                                        web::post().to_async(routes::submit_scabbard_payload),
                                    )),
                            ),
                    )
                    .service(
                        web::scope("/keys").service(
                            web::resource("/{public_key}")
                                .route(web::get().to_async(routes::fetch_key_info)),
                        ),
                    )
            })
            .bind(bind_url)?
            .disable_signals()
            .system_exit()
            .start();

            tx.send(addr).map_err(|err| {
                RestApiServerError::StartUpError(format!("Unable to send Server Addr: {}", err))
            })?;
            sys.run()?;

            info!("Rest API terminating");

            Ok(())
        })?;

    let addr = rx.recv().map_err(|err| {
        RestApiServerError::StartUpError(format!("Unable to receive Server Addr: {}", err))
    })?;

    let do_shutdown = Box::new(move || {
        debug!("Shutting down Rest API");
        if let Err(err) = addr.stop(true).wait() {
            error!("Failed to shutdown rest api cleanly: {:?}", err);
        }
        debug!("Graceful signal sent to Rest API");

        Ok(())
    });

    Ok((RestApiShutdownHandle { do_shutdown }, join_handle))
}

fn handle_error(err: Box<dyn ActixError::ResponseError>) -> ActixError::Error {
    let message = err.to_string();
    ActixError::InternalError::from_response(
        err,
        HttpResponse::BadRequest().json(ErrorResponse::bad_request(&message)),
    )
    .into()
}
