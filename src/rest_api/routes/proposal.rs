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
use std::time::{Duration, SystemTime};

use actix_web::{error, web, Error, HttpResponse};
use futures::Future;
use openssl::hash::{hash, MessageDigest};
use protobuf::Message;
use splinter::admin::messages::CircuitProposalVote;
use splinter::node_registry::Node;
use splinter::protos::admin::{
    CircuitManagementPayload, CircuitManagementPayload_Action as Action,
    CircuitManagementPayload_Header as Header,
};

use super::{
    get_response_paging_info, validate_limit, ErrorResponse, SuccessResponse, DEFAULT_LIMIT,
    DEFAULT_OFFSET,
};
use crate::rest_api::RestApiResponseError;
use db_models::models::{ConsortiumProposal, ConsortiumMember};

#[derive(Debug, Serialize)]
struct ApiConsortiumProposal {
    proposal_id: String,
    circuit_id: String,
    circuit_hash: String,
    members: Vec<ApiConsortiumMember>,
    requester: String,
    requester_node_id: String,
    created_time: u64,
    updated_time: u64,
}

impl ApiConsortiumProposal {
    fn from(db_proposal: ConsortiumProposal, db_members: Vec<ConsortiumMember>) -> Self {
        ApiConsortiumProposal {
            proposal_id: db_proposal.id.to_string(),
            circuit_id: db_proposal.circuit_id.to_string(),
            circuit_hash: db_proposal.circuit_hash.to_string(),
            members: db_members
                .into_iter()
                .map(ApiConsortiumMember::from)
                .collect(),
            requester: db_proposal.requester.to_string(),
            requester_node_id: db_proposal.requester_node_id.to_string(),
            created_time: db_proposal
                .created_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::new(0, 0))
                .as_secs(),
            updated_time: db_proposal
                .updated_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::new(0, 0))
                .as_secs(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiConsortiumMember {
    node_id: String,
    endpoint: String,
}

impl ApiConsortiumMember {
    fn from(db_circuit_member: ConsortiumMember) -> Self {
        ApiConsortiumMember {
            node_id: db_circuit_member.node_id.to_string(),
            endpoint: db_circuit_member.endpoint.to_string(),
        }
    }
}

pub fn proposal_vote(
    vote: web::Json<CircuitProposalVote>,
    node_info: web::Data<Node>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let node_identity = node_info.identity.to_string();
    Box::new(
        // TODO: If proposal exists
        web::block(move || Ok(())).then(|res| match res {
            Ok(()) => match make_payload(vote.into_inner(), node_identity) {
                Ok(bytes) => Ok(HttpResponse::Ok()
                    .json(SuccessResponse::new(json!({ "payload_bytes": bytes })))),
                Err(err) => {
                    debug!("Failed to prepare circuit management payload {}", err);
                    Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
                }
            },
            Err(err) => match err {
                error::BlockingError::Error(err) => {
                    match err {
                        RestApiResponseError::NotFound(err) => Ok(HttpResponse::NotFound()
                            .json(ErrorResponse::not_found(&err.to_string()))),
                        RestApiResponseError::BadRequest(err) => Ok(HttpResponse::BadRequest()
                            .json(ErrorResponse::bad_request(&err.to_string()))),
                        _ => Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error())),
                    }
                }
                error::BlockingError::Canceled => {
                    debug!("Internal Server Error: {}", err);
                    Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
                }
            },
        }),
    )
}

fn make_payload(
    vote: CircuitProposalVote,
    local_node: String,
) -> Result<Vec<u8>, RestApiResponseError> {
    let vote_proto = vote.into_proto();
    let vote_bytes = vote_proto.write_to_bytes()?;
    let hashed_bytes = hash(MessageDigest::sha512(), &vote_bytes)?;

    let mut header = Header::new();
    header.set_action(Action::CIRCUIT_PROPOSAL_VOTE);
    header.set_payload_sha512(hashed_bytes.to_vec());
    header.set_requester_node_id(local_node);
    let header_bytes = header.write_to_bytes()?;

    let mut circuit_management_payload = CircuitManagementPayload::new();
    circuit_management_payload.set_header(header_bytes);
    circuit_management_payload.set_circuit_proposal_vote(vote_proto);
    let payload_bytes = circuit_management_payload.write_to_bytes()?;
    Ok(payload_bytes)
}
