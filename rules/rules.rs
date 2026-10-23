use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub position: i32,
    pub expression: String,
    pub actions: Vec<Action>,

    pub project_id: Option<Uuid>,
    pub ruleset_id: Option<Uuid>,
}

pub type CompiledExpression = bel::Program;
pub type Context<'a> = bel::Context<'a>;

// pub struct CompiledRule {
//     pub id: Uuid,
//     pub updated_at: DateTime<Utc>,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Block {},
    Captcha {},
    Allow {},
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Unspecified(String),
    #[error("Expression is not valid: {0}")]
    ExpressionIsNotValid(String),
    #[error("{0}")]
    ParseIntError(String),
    #[error("{0}")]
    AddrParseError(String),
    #[error("invalid CIDR format, expected <network>/<prefix>, got: {0}")]
    InvalidCidrFormatError(String),
}

pub fn compile_expression(expression: &str) -> Result<CompiledExpression, Error> {
    let program = match std::panic::catch_unwind(|| bel::Program::compile(expression)) {
        Ok(Ok(program)) => program,
        Ok(Err(err)) => return Err(Error::ExpressionIsNotValid(err.to_string())),
        Err(_) => return Err(Error::ExpressionIsNotValid("invalid input".to_string())),
    };

    return Ok(program);
}

pub fn validate_expression(expression: &str) -> Result<(), Error> {
    if expression.is_empty() {
        return Err(Error::ExpressionIsNotValid("expression is empty".to_string()));
    }

    let program = match std::panic::catch_unwind(|| bel::Program::compile(expression)) {
        Ok(Ok(program)) => program,
        Ok(Err(err)) => return Err(Error::ExpressionIsNotValid(err.to_string())),
        Err(_) => return Err(Error::ExpressionIsNotValid("invalid input".to_string())),
    };
    let references = program.references();

    // validate functions
    let functions = references.functions();
    if functions.contains(&"@in") {
        return Err(Error::ExpressionIsNotValid("unknown operator: in".to_string()));
    }

    // validate variables
    // TODO

    return Ok(());
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::ParseIntError(err.to_string())
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Error::AddrParseError(err.to_string())
    }
}
