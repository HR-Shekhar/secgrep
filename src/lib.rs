pub mod cli;
pub mod config;
pub mod detect;
pub mod engine;
pub mod error;
pub mod finding;
pub mod git;
pub mod history;
pub mod hook;
pub mod redact;
pub mod remediate;
pub mod report;
pub mod score;
pub mod validate;
pub mod walk;

pub use error::Error;

pub fn run() -> Result<i32, Error> {
    cli::run()
}
