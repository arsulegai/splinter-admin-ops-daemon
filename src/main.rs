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

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

mod application_metadata;
mod config;
mod error;
mod rest_api;

use std::thread;

use flexi_logger::{style, DeferredNow, LogSpecBuilder, Logger};
use log::Record;
use sawtooth_sdk::signing::create_context;
use splinter::events::Reactor;

use crate::config::{get_node, GameroomConfigBuilder};
use crate::error::GameroomDaemonError;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

// format for logs
pub fn log_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "[{}] T[{:?}] {} [{}] {}",
        now.now().format("%Y-%m-%d %H:%M:%S%.3f"),
        thread::current().name().unwrap_or("<unnamed>"),
        record.level(),
        record.module_path().unwrap_or("<unnamed>"),
        style(level, &record.args()),
    )
}

fn run() -> Result<(), GameroomDaemonError> {
    let matches = clap_app!(myapp =>
        (name: APP_NAME)
        (version: VERSION)
        (author: "Walmart Inc.")
        (about: "Daemon Package for PO Administration")
        (@arg verbose: -v +multiple "Log verbosely")
        (@arg database_url: --("database-url") +takes_value "Database connection for Gameroom rest API")
        (@arg bind: -b --bind +takes_value "connection endpoint for Administration Service rest API")
        (@arg splinterd_url: --("splinterd-url") +takes_value "connection endpoint to SplinterD rest API")
    )
    .get_matches();

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    let mut log_spec_builder = LogSpecBuilder::new();
    log_spec_builder.default(log_level);
    log_spec_builder.module("hyper", log::LevelFilter::Warn);
    log_spec_builder.module("tokio", log::LevelFilter::Warn);
    log_spec_builder.module("trust_dns", log::LevelFilter::Warn);

    Logger::with(log_spec_builder.build())
        .format(log_format)
        .start()?;

    let config = GameroomConfigBuilder::default()
        .with_cli_args(&matches)
        .build()?;

    // Generate a public/private key pair
    let context = create_context("secp256k1")?;
    let private_key = context.new_random_private_key()?;
    let public_key = context.get_public_key(&*private_key)?;

    // Get splinterd node information
    let node = get_node(config.splinterd_url())?;

    let reactor = Reactor::new();

    let (rest_api_shutdown_handle, rest_api_join_handle) = rest_api::run(
        config.rest_api_endpoint(),
        config.splinterd_url(),
        node,
        public_key.as_hex(),
    )?;

    ctrlc::set_handler(move || {
        info!("Received Shutdown");

        if let Err(err) = rest_api_shutdown_handle.shutdown() {
            error!("Unable to cleanly shutdown REST API server: {}", err);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let _ = rest_api_join_handle.join();

    if let Err(err) = reactor.shutdown() {
        error!(
            "Unable to cleanly shutdown application authorization handler reactor: {}",
            err
        );
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        error!("{}", e);
        std::process::exit(1);
    }
}
