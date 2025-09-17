use core::fmt;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::debug;

use crate::{Error, config::ListConfig};

enum List {
    String { items: Vec<String> },
    Int { items: Vec<i64> },
    Ip { items: Vec<IpNetwork> },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    String,
    Int,
    Ip,
}

impl fmt::Display for ListType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let enum_str = match self {
            Self::Int => "Int",
            Self::Ip => "Ip",
            Self::String => "String",
        };
        return write!(formatter, "{}", enum_str);
    }
}

impl FromStr for ListType {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.to_ascii_lowercase();
        match value.as_str() {
            "int" => Ok(Self::Int),
            "ip" => Ok(Self::Ip),
            "string" => Ok(Self::String),
            _ => Err(Error::Unspecified(format!("{value} is not a valid ListType"))),
        }
    }
}

pub async fn load_lists(lists_config: &HashMap<String, ListConfig>) -> Result<Arc<bel::Value>, Error> {
    // TODO: do we really need to Arc the lists, as under the hood heap-allocated values are already
    // Arc
    let mut lists = HashMap::with_capacity(lists_config.len());

    for (list_name, list_config) in lists_config {
        let list = load_list(&list_config.file, list_config.r#type).await?;
        debug!("list successfully loaded: {list_name} from {}", list_config.file);
        lists.insert(list_name.clone(), list);
    }

    return Ok(Arc::new(lists_to_bel_value(lists)));
}

async fn load_list(path: &str, type_: ListType) -> Result<List, Error> {
    let file_content = fs::read(path)
        .await
        .map_err(|err| Error::Config(format!("error reading list {path}: {err}")))?;

    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(file_content.as_slice());

    let mut list = match type_ {
        ListType::String => List::String { items: Vec::new() },
        ListType::Int => List::Int { items: Vec::new() },
        ListType::Ip => List::Ip { items: Vec::new() },
    };

    let mut line_number = 0;
    for record in csv_reader.records() {
        line_number += 1;

        let record = record
            .map_err(|err| Error::Unspecified(format!("error parsing list {path} at line {line_number}: {err}")))?;
        if record.len() > 2 || record.len() < 1 {
            return Err(Error::Unspecified(format!(
                "error parsing list {path} at line {line_number}: invalid number of columns. Min: 1, Max: 2"
            )));
        }

        let item_value = record[0].trim().to_string();
        match &mut list {
            List::String { items } => items.push(item_value),
            List::Int { items } => {
                let item_int: i64 = item_value.parse().map_err(|err| {
                    Error::Unspecified(format!(
                        "error parsing list {path} at line {line_number}: error parsing int: {err}"
                    ))
                })?;
                items.push(item_int);
            }
            List::Ip { items } => {
                let item: IpNetwork = item_value.parse().map_err(|err| {
                    Error::Unspecified(format!(
                        "error parsing list {path} at line {line_number}: error parsing IP network: {err}"
                    ))
                })?;
                items.push(item);
            }
        }
    }

    return Ok(list);
}

fn lists_to_bel_value(lists: HashMap<String, List>) -> bel::Value {
    lists
        .into_iter()
        .map(|(key, value)| match value {
            List::String { items } => (key.clone(), items.into()),
            List::Int { items } => (key.clone(), items.into()),
            List::Ip { items } => (key.clone(), items.into()),
        })
        .collect::<HashMap<_, bel::Value>>()
        .into()
}
