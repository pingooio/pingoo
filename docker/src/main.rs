use std::collections::HashMap;

use docker::{Client, model::ListContainersOptions};

#[tokio::main]
async fn main() {
    let client = Client::new(None);

    let mut filters = HashMap::new();
    filters.insert("label".to_string(), vec!["my.service=test".to_string()]);
    let containers = client
        .list_containers(Some(ListContainersOptions {
            filters: filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    println!("{containers:?}");
}
