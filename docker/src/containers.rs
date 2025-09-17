use crate::{
    Client, Error,
    model::{ContainerSummary, ListContainersOptions},
};

impl Client {
    pub async fn list_containers(
        &self,
        options: Option<ListContainersOptions>,
    ) -> Result<Vec<ContainerSummary>, Error> {
        return self.send_request("/containers/json", options, None).await;
    }
}
