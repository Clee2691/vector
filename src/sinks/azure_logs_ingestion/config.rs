use std::sync::Arc;

use azure_core::auth::TokenCredential;
use azure_core::HttpClient;
use azure_identity::{
    AutoRefreshingTokenCredential, ClientSecretCredential, TokenCredentialOptions,
};
use vector_lib::{configurable::configurable_component, schema, sensitive_string::SensitiveString};
use vrl::value::Kind;

use crate::{
    http::HttpClient as VectorHttpClient,
    sinks::{
        prelude::*,
        util::{RealtimeSizeBasedDefaultBatchSettings, UriSerde, http::HttpStatusRetryLogic},
    },
};

use super::{
    service::{AzureLogsIngestionResponse, AzureLogsIngestionService},
    sink::AzureLogsIngestionSink,
};

const MAX_BATCH_SIZE: usize = 30 * 1024 * 1024;

pub(super) fn default_scope() -> String {
    "https://monitor.azure.com".into()
}

pub(super) fn default_timestamp_field() -> String {
    "TimeGenerated".into()
}

/// Configuration for the `azure_logs_ingestion` sink.
#[configurable_component(sink(
    "azure_logs_ingestion",
    "Publish log events to the Azure Monitor Logs Ingestion API."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AzureLogsIngestionConfig {
    /// The Data collection endpoint URI associated with the Log Analytics workspace.
    #[configurable(metadata(
        docs::examples = "https://my-dce-5kyl.eastus-1.ingest.monitor.azure.com"
    ))]
    pub endpoint: String,

    /// The Data collection rule immutable ID for the Data collection endpoint.
    #[configurable(metadata(docs::examples = "dcr-000a00a000a00000a000000aa000a0aa"))]
    pub dcr_immutable_id: String,

    /// The Stream name for the Data collection rule.
    #[configurable(metadata(docs::examples = "Custom-MyTable"))]
    pub stream_name: String,

    #[configurable(derived)]
    #[serde(default)]
    pub auth: AzureAuthentication,

    /// Token scope for dedicated Azure regions.
    /// The SDK appends `/.default` automatically — provide only the base resource URL.
    #[configurable(metadata(docs::examples = "https://monitor.azure.us"))]
    #[configurable(metadata(docs::examples = "https://monitor.azure.cn"))]
    #[serde(default = "default_scope")]
    pub(super) token_scope: String,

    /// The destination field (column) for the timestamp.
    #[configurable(metadata(docs::examples = "EventStartTime"))]
    #[configurable(metadata(docs::examples = "Timestamp"))]
    #[serde(default = "default_timestamp_field")]
    pub timestamp_field: String,

    #[configurable(derived)]
    #[serde(default, skip_serializing_if = "crate::serde::is_default")]
    pub encoding: Transformer,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<RealtimeSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,
}

impl Default for AzureLogsIngestionConfig {
    fn default() -> Self {
        Self {
            endpoint: Default::default(),
            dcr_immutable_id: Default::default(),
            stream_name: Default::default(),
            auth: Default::default(),
            token_scope: default_scope(),
            timestamp_field: default_timestamp_field(),
            encoding: Default::default(),
            batch: Default::default(),
            request: Default::default(),
            tls: None,
            acknowledgements: Default::default(),
        }
    }
}

/// Authentication configuration for Azure Logs Ingestion.
#[configurable_component]
#[derive(Clone, Debug, Derivative, Eq, PartialEq)]
#[derivative(Default)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "azure_credential_kind")]
pub enum AzureAuthentication {
    /// Use Azure AD service principal client credentials.
    #[derivative(Default)]
    ClientSecretCredential {
        /// The Azure Tenant ID.
        #[configurable(metadata(docs::examples = "00000000-0000-0000-0000-000000000000"))]
        azure_tenant_id: String,

        /// The Azure Client ID.
        #[configurable(metadata(docs::examples = "00000000-0000-0000-0000-000000000000"))]
        azure_client_id: String,

        /// The Azure Client Secret.
        #[configurable(metadata(
            docs::examples = "00-00~000000-0000000~0000000000000000000"
        ))]
        azure_client_secret: SensitiveString,
    },
}

impl AzureAuthentication {
    pub async fn credential(
        &self,
    ) -> crate::Result<Arc<dyn TokenCredential>> {
        match self {
            Self::ClientSecretCredential {
                azure_tenant_id,
                azure_client_id,
                azure_client_secret,
            } => {
                if azure_tenant_id.is_empty() {
                    return Err("`auth.azure_tenant_id` is blank; provide tenant ID, client ID, and secret.".into());
                }
                if azure_client_id.is_empty() {
                    return Err("`auth.azure_client_id` is blank; provide tenant ID, client ID, and secret.".into());
                }
                if azure_client_secret.inner().is_empty() {
                    return Err("`auth.azure_client_secret` is blank; provide tenant ID, client ID, and secret.".into());
                }

                let http_client: Arc<dyn HttpClient> = azure_core::new_http_client();
                let secret: String = azure_client_secret.inner().into();

                let credential = ClientSecretCredential::new(
                    http_client,
                    azure_tenant_id.clone(),
                    azure_client_id.clone(),
                    secret,
                    TokenCredentialOptions::default(),
                );

                let credential: Arc<dyn TokenCredential> = Arc::new(credential);
                let auto_credential = AutoRefreshingTokenCredential::new(credential);

                Ok(Arc::new(auto_credential))
            }
        }
    }
}

impl AzureLogsIngestionConfig {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn build_inner(
        &self,
        cx: SinkContext,
        endpoint: UriSerde,
        dcr_immutable_id: String,
        stream_name: String,
        credential: Arc<dyn TokenCredential>,
        token_scope: String,
        timestamp_field: String,
    ) -> crate::Result<(VectorSink, Healthcheck)> {
        let endpoint = endpoint.with_default_parts().uri;
        let protocol = crate::http::get_http_scheme_from_uri(&endpoint).to_string();

        let batch_settings = self
            .batch
            .validate()?
            .limit_max_bytes(MAX_BATCH_SIZE)?
            .into_batcher_settings()?;

        let tls_settings = TlsSettings::from_options(self.tls.as_ref())?;
        let client = VectorHttpClient::new(tls_settings, cx.proxy())?;

        let service = AzureLogsIngestionService::new(
            client,
            endpoint,
            dcr_immutable_id,
            stream_name,
            credential,
            token_scope,
        )?;
        let healthcheck = service.healthcheck();

        let retry_logic =
            HttpStatusRetryLogic::new(|res: &AzureLogsIngestionResponse| res.http_status);
        let request_settings = self.request.into_settings();
        let service = ServiceBuilder::new()
            .settings(request_settings, retry_logic)
            .service(service);

        let sink = AzureLogsIngestionSink::new(
            batch_settings,
            self.encoding.clone(),
            service,
            timestamp_field,
            protocol,
        );

        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }
}

impl_generate_config_from_default!(AzureLogsIngestionConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "azure_logs_ingestion")]
impl SinkConfig for AzureLogsIngestionConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let endpoint: UriSerde = self.endpoint.parse()?;
        let credential: Arc<dyn TokenCredential> = self.auth.credential().await?;

        self.build_inner(
            cx,
            endpoint,
            self.dcr_immutable_id.clone(),
            self.stream_name.clone(),
            credential,
            self.token_scope.clone(),
            self.timestamp_field.clone(),
        )
        .await
    }

    fn input(&self) -> Input {
        let requirements =
            schema::Requirement::empty().optional_meaning("timestamp", Kind::timestamp());
        Input::log().with_schema_requirement(requirements)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}
