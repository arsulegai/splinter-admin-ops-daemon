// Copyright 2019 Cargill Incorporated
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
use std::collections::HashMap;

use actix_web::{client::Client, error, http::StatusCode, web, Error, HttpResponse};
use futures::{Future, IntoFuture};
use openssl::hash::{hash, MessageDigest};
use protobuf::Message;
use splinter::admin::messages::{
    AuthorizationType, CreateCircuit, DurabilityType, PersistenceType, RouteType, SplinterNode,
    SplinterService,
};
use splinter::node_registry::Node;
use splinter::protos::admin::{
    CircuitManagementPayload, CircuitManagementPayload_Action as Action,
    CircuitManagementPayload_Header as Header,
};
use uuid::Uuid;

use crate::application_metadata::ApplicationMetadata;
use crate::rest_api::{ConsortiumData, RestApiResponseError};

use super::{
    get_response_paging_info, validate_limit, ErrorResponse, SuccessResponse, DEFAULT_LIMIT,
    DEFAULT_OFFSET,
};
use db_models::models::Consortium;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateConsortiumForm {
    alias: String,
    members: Vec<String>,
}

pub fn propose_consortium(
    create_consortium: web::Json<CreateConsortiumForm>,
    node_info: web::Data<Node>,
    client: web::Data<Client>,
    splinterd_url: web::Data<String>,
    consortium_data: web::Data<ConsortiumData>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    fetch_node_information(&create_consortium.members, &splinterd_url, client).then(move |resp| {
        let nodes = match resp {
            Ok(nodes) => nodes,
            Err(err) => match err {
                RestApiResponseError::BadRequest(message) => {
                    return HttpResponse::BadRequest()
                        .json(ErrorResponse::bad_request(&message.to_string()))
                        .into_future();
                }
                _ => {
                    debug!("Failed to fetch node information: {}", err);
                    return HttpResponse::InternalServerError()
                        .json(ErrorResponse::internal_error())
                        .into_future();
                }
            },
        };

        let mut members = nodes
            .iter()
            .map(|node| SplinterNode {
                node_id: node.identity.to_string(),
                endpoint: node
                    .metadata
                    .get("endpoint")
                    .unwrap_or(&"".to_string())
                    .to_string(),
            })
            .collect::<Vec<SplinterNode>>();

        members.push(SplinterNode {
            node_id: node_info.identity.to_string(),
            endpoint: node_info
                .metadata
                .get("endpoint")
                .unwrap_or(&"".to_string())
                .to_string(),
        });
        let partial_circuit_id = members.iter().fold(String::new(), |mut acc, member| {
            acc.push_str(&format!("::{}", member.node_id));
            acc
        });

        let scabbard_admin_keys = vec![consortium_data.get_ref().public_key.clone()];

        let mut scabbard_args = vec![];
        scabbard_args.push((
            "admin_keys".into(),
            match serde_json::to_string(&scabbard_admin_keys) {
                Ok(s) => s,
                Err(err) => {
                    debug!("Failed to serialize scabbard admin keys: {}", err);
                    return HttpResponse::InternalServerError()
                        .json(ErrorResponse::internal_error())
                        .into_future();
                }
            },
        ));

        let mut roster = vec![];
        for node in members.iter() {
            let peer_services = match serde_json::to_string(
                &members
                    .iter()
                    .filter_map(|other_node| {
                        if other_node.node_id != node.node_id {
                            Some(format!("consortium_{}", other_node.node_id))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            ) {
                Ok(s) => s,
                Err(err) => {
                    debug!("Failed to serialize peer services: {}", err);
                    return HttpResponse::InternalServerError()
                        .json(ErrorResponse::internal_error())
                        .into_future();
                }
            };

            let mut service_args = scabbard_args.clone();
            service_args.push(("peer_services".into(), peer_services));

            roster.push(SplinterService {
                service_id: format!("consortium_{}", node.node_id),
                service_type: "scabbard".to_string(),
                allowed_nodes: vec![node.node_id.to_string()],
                arguments: service_args,
            });
        }

        // TODO: Check uniqueness
        let application_metadata = match ApplicationMetadata::new(&create_consortium.alias, &scabbard_admin_keys)
                .to_bytes()
            {
                Ok(bytes) => bytes,
                Err(err) => {
                    debug!("Failed to serialize application metadata: {}", err);
                    return HttpResponse::InternalServerError()
                        .json(ErrorResponse::internal_error())
                        .into_future();
                }
            };

        let create_request = CreateCircuit {
            circuit_id: format!(
                "consortium{}::{}",
                partial_circuit_id,
                Uuid::new_v4().to_string()
            ),
            roster,
            members,
            authorization_type: AuthorizationType::Trust,
            persistence: PersistenceType::Any,
            durability: DurabilityType::NoDurability,
            routes: RouteType::Any,
            circuit_management_type: "consortium".to_string(),
            application_metadata,
        };

        let payload_bytes = match make_payload(create_request, node_info.identity.to_string()) {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!("Failed to make circuit management payload: {}", err);
                return HttpResponse::InternalServerError()
                    .json(ErrorResponse::internal_error())
                    .into_future();
            }
        };

        HttpResponse::Ok()
            .json(SuccessResponse::new(json!({
                "payload_bytes": payload_bytes
            })))
            .into_future()
    })
}

fn fetch_node_information(
    node_ids: &[String],
    splinterd_url: &str,
    client: web::Data<Client>,
) -> Box<dyn Future<Item = Vec<Node>, Error = RestApiResponseError>> {
    let node_ids = node_ids.to_owned();
    Box::new(
        client
            .get(&format!("{}/nodes?limit={}", splinterd_url, std::i64::MAX))
            .send()
            .map_err(|err| {
                RestApiResponseError::InternalError(format!("Failed to send request {}", err))
            })
            .and_then(move |mut resp| {
                let body = resp.body().wait().map_err(|err| {
                    RestApiResponseError::InternalError(format!(
                        "Failed to receive response body {}",
                        err
                    ))
                })?;
                match resp.status() {
                    StatusCode::OK => {
                        let list_reponse: SuccessResponse<Vec<Node>> =
                            serde_json::from_slice(&body).map_err(|err| {
                                RestApiResponseError::InternalError(format!(
                                    "Failed to parse response body {}",
                                    err
                                ))
                            })?;
                        let nodes = node_ids.into_iter().try_fold(vec![], |mut acc, node_id| {
                            if let Some(node) = list_reponse
                                .data
                                .iter()
                                .find(|node| node.identity == node_id)
                            {
                                acc.push(node.clone());
                                Ok(acc)
                            } else {
                                Err(RestApiResponseError::BadRequest(format!(
                                    "Could not find node with id {}",
                                    node_id
                                )))
                            }
                        })?;

                        Ok(nodes)
                    }
                    StatusCode::BAD_REQUEST => {
                        let message: String = serde_json::from_slice(&body).map_err(|err| {
                            RestApiResponseError::InternalError(format!(
                                "Failed to parse response body {}",
                                err
                            ))
                        })?;
                        Err(RestApiResponseError::BadRequest(message))
                    }
                    _ => {
                        let message: String = serde_json::from_slice(&body).map_err(|err| {
                            RestApiResponseError::InternalError(format!(
                                "Failed to parse response body {}",
                                err
                            ))
                        })?;

                        Err(RestApiResponseError::InternalError(message))
                    }
                }
            }),
    )
}

fn make_payload(
    create_request: CreateCircuit,
    local_node: String,
) -> Result<Vec<u8>, RestApiResponseError> {
    let circuit_proto = create_request.into_proto()?;
    let circuit_bytes = circuit_proto.write_to_bytes()?;
    let hashed_bytes = hash(MessageDigest::sha512(), &circuit_bytes)?;

    let mut header = Header::new();
    header.set_action(Action::CIRCUIT_CREATE_REQUEST);
    header.set_payload_sha512(hashed_bytes.to_vec());
    header.set_requester_node_id(local_node);
    let header_bytes = header.write_to_bytes()?;

    let mut circuit_management_payload = CircuitManagementPayload::new();
    circuit_management_payload.set_header(header_bytes);
    circuit_management_payload.set_circuit_create_request(circuit_proto);
    let payload_bytes = circuit_management_payload.write_to_bytes()?;
    Ok(payload_bytes)
}
