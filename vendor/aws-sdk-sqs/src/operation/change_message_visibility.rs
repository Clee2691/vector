// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
/// Orchestration and serialization glue logic for `ChangeMessageVisibility`.
#[derive(::std::clone::Clone, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChangeMessageVisibility;
impl ChangeMessageVisibility {
    /// Creates a new `ChangeMessageVisibility`
    pub fn new() -> Self {
        Self
    }
    pub(crate) async fn orchestrate(
        runtime_plugins: &::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
        input: crate::operation::change_message_visibility::ChangeMessageVisibilityInput,
    ) -> ::std::result::Result<
        crate::operation::change_message_visibility::ChangeMessageVisibilityOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::change_message_visibility::ChangeMessageVisibilityError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let map_err = |err: ::aws_smithy_runtime_api::client::result::SdkError<
            ::aws_smithy_runtime_api::client::interceptors::context::Error,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >| {
            err.map_service_error(|err| {
                err.downcast::<crate::operation::change_message_visibility::ChangeMessageVisibilityError>()
                    .expect("correct error type")
            })
        };
        let context = Self::orchestrate_with_stop_point(runtime_plugins, input, ::aws_smithy_runtime::client::orchestrator::StopPoint::None)
            .await
            .map_err(map_err)?;
        let output = context.finalize().map_err(map_err)?;
        ::std::result::Result::Ok(
            output
                .downcast::<crate::operation::change_message_visibility::ChangeMessageVisibilityOutput>()
                .expect("correct output type"),
        )
    }

    pub(crate) async fn orchestrate_with_stop_point(
        runtime_plugins: &::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
        input: crate::operation::change_message_visibility::ChangeMessageVisibilityInput,
        stop_point: ::aws_smithy_runtime::client::orchestrator::StopPoint,
    ) -> ::std::result::Result<
        ::aws_smithy_runtime_api::client::interceptors::context::InterceptorContext,
        ::aws_smithy_runtime_api::client::result::SdkError<
            ::aws_smithy_runtime_api::client::interceptors::context::Error,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = ::aws_smithy_runtime_api::client::interceptors::context::Input::erase(input);
        ::aws_smithy_runtime::client::orchestrator::invoke_with_stop_point("sqs", "ChangeMessageVisibility", input, runtime_plugins, stop_point).await
    }

    pub(crate) fn operation_runtime_plugins(
        client_runtime_plugins: ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
        client_config: &crate::config::Config,
        config_override: ::std::option::Option<crate::config::Builder>,
    ) -> ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins {
        let mut runtime_plugins = client_runtime_plugins.with_operation_plugin(Self::new());
        runtime_plugins = runtime_plugins.with_client_plugin(crate::auth_plugin::DefaultAuthOptionsPlugin::new(vec![
            ::aws_runtime::auth::sigv4::SCHEME_ID,
        ]));
        if let ::std::option::Option::Some(config_override) = config_override {
            for plugin in config_override.runtime_plugins.iter().cloned() {
                runtime_plugins = runtime_plugins.with_operation_plugin(plugin);
            }
            runtime_plugins = runtime_plugins.with_operation_plugin(crate::config::ConfigOverrideRuntimePlugin::new(
                config_override,
                client_config.config.clone(),
                &client_config.runtime_components,
            ));
        }
        runtime_plugins
    }
}
impl ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugin for ChangeMessageVisibility {
    fn config(&self) -> ::std::option::Option<::aws_smithy_types::config_bag::FrozenLayer> {
        let mut cfg = ::aws_smithy_types::config_bag::Layer::new("ChangeMessageVisibility");

        cfg.store_put(::aws_smithy_runtime_api::client::ser_de::SharedRequestSerializer::new(
            ChangeMessageVisibilityRequestSerializer,
        ));
        cfg.store_put(::aws_smithy_runtime_api::client::ser_de::SharedResponseDeserializer::new(
            ChangeMessageVisibilityResponseDeserializer,
        ));

        cfg.store_put(::aws_smithy_runtime_api::client::auth::AuthSchemeOptionResolverParams::new(
            ::aws_smithy_runtime_api::client::auth::static_resolver::StaticAuthSchemeOptionResolverParams::new(),
        ));

        cfg.store_put(::aws_smithy_http::operation::Metadata::new("ChangeMessageVisibility", "sqs"));
        let mut signing_options = ::aws_runtime::auth::SigningOptions::default();
        signing_options.double_uri_encode = true;
        signing_options.content_sha256_header = false;
        signing_options.normalize_uri_path = true;
        signing_options.payload_override = None;

        cfg.store_put(::aws_runtime::auth::SigV4OperationSigningConfig {
            signing_options,
            ..::std::default::Default::default()
        });

        ::std::option::Option::Some(cfg.freeze())
    }

    fn runtime_components(
        &self,
        _: &::aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder,
    ) -> ::std::borrow::Cow<'_, ::aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder> {
        #[allow(unused_mut)]
        let mut rcb = ::aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder::new("ChangeMessageVisibility")
            .with_interceptor(
                ::aws_smithy_runtime::client::stalled_stream_protection::StalledStreamProtectionInterceptor::new(
                    ::aws_smithy_runtime::client::stalled_stream_protection::StalledStreamProtectionInterceptorKind::ResponseBody,
                ),
            )
            .with_interceptor(ChangeMessageVisibilityEndpointParamsInterceptor)
            .with_retry_classifier(::aws_smithy_runtime::client::retries::classifiers::TransientErrorClassifier::<
                crate::operation::change_message_visibility::ChangeMessageVisibilityError,
            >::new())
            .with_retry_classifier(::aws_smithy_runtime::client::retries::classifiers::ModeledAsRetryableClassifier::<
                crate::operation::change_message_visibility::ChangeMessageVisibilityError,
            >::new())
            .with_retry_classifier(::aws_runtime::retries::classifiers::AwsErrorCodeClassifier::<
                crate::operation::change_message_visibility::ChangeMessageVisibilityError,
            >::new());

        ::std::borrow::Cow::Owned(rcb)
    }
}

#[derive(Debug)]
struct ChangeMessageVisibilityResponseDeserializer;
impl ::aws_smithy_runtime_api::client::ser_de::DeserializeResponse for ChangeMessageVisibilityResponseDeserializer {
    fn deserialize_nonstreaming(
        &self,
        response: &::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    ) -> ::aws_smithy_runtime_api::client::interceptors::context::OutputOrError {
        let (success, status) = (response.status().is_success(), response.status().as_u16());
        let headers = response.headers();
        let body = response.body().bytes().expect("body loaded");
        #[allow(unused_mut)]
        let mut force_error = false;
        ::tracing::debug!(request_id = ?::aws_types::request_id::RequestId::request_id(response));
        let parse_result = if !success && status != 200 || force_error {
            crate::protocol_serde::shape_change_message_visibility::de_change_message_visibility_http_error(status, headers, body)
        } else {
            crate::protocol_serde::shape_change_message_visibility::de_change_message_visibility_http_response(status, headers, body)
        };
        crate::protocol_serde::type_erase_result(parse_result)
    }
}
#[derive(Debug)]
struct ChangeMessageVisibilityRequestSerializer;
impl ::aws_smithy_runtime_api::client::ser_de::SerializeRequest for ChangeMessageVisibilityRequestSerializer {
    #[allow(unused_mut, clippy::let_and_return, clippy::needless_borrow, clippy::useless_conversion)]
    fn serialize_input(
        &self,
        input: ::aws_smithy_runtime_api::client::interceptors::context::Input,
        _cfg: &mut ::aws_smithy_types::config_bag::ConfigBag,
    ) -> ::std::result::Result<::aws_smithy_runtime_api::client::orchestrator::HttpRequest, ::aws_smithy_runtime_api::box_error::BoxError> {
        let input = input
            .downcast::<crate::operation::change_message_visibility::ChangeMessageVisibilityInput>()
            .expect("correct type");
        let _header_serialization_settings = _cfg
            .load::<crate::serialization_settings::HeaderSerializationSettings>()
            .cloned()
            .unwrap_or_default();
        let mut request_builder = {
            fn uri_base(
                _input: &crate::operation::change_message_visibility::ChangeMessageVisibilityInput,
                output: &mut ::std::string::String,
            ) -> ::std::result::Result<(), ::aws_smithy_types::error::operation::BuildError> {
                use ::std::fmt::Write as _;
                ::std::write!(output, "/").expect("formatting should succeed");
                ::std::result::Result::Ok(())
            }
            #[allow(clippy::unnecessary_wraps)]
            fn update_http_builder(
                input: &crate::operation::change_message_visibility::ChangeMessageVisibilityInput,
                builder: ::http::request::Builder,
            ) -> ::std::result::Result<::http::request::Builder, ::aws_smithy_types::error::operation::BuildError> {
                let mut uri = ::std::string::String::new();
                uri_base(input, &mut uri)?;
                ::std::result::Result::Ok(builder.method("POST").uri(uri))
            }
            let mut builder = update_http_builder(&input, ::http::request::Builder::new())?;
            builder = _header_serialization_settings.set_default_header(builder, ::http::header::CONTENT_TYPE, "application/x-amz-json-1.0");
            builder = _header_serialization_settings.set_default_header(
                builder,
                ::http::header::HeaderName::from_static("x-amz-target"),
                "AmazonSQS.ChangeMessageVisibility",
            );
            builder
        };
        let body = ::aws_smithy_types::body::SdkBody::from(
            crate::protocol_serde::shape_change_message_visibility::ser_change_message_visibility_input(&input)?,
        );
        if let Some(content_length) = body.content_length() {
            let content_length = content_length.to_string();
            request_builder = _header_serialization_settings.set_default_header(request_builder, ::http::header::CONTENT_LENGTH, &content_length);
        }
        ::std::result::Result::Ok(request_builder.body(body).expect("valid request").try_into().unwrap())
    }
}
#[derive(Debug)]
struct ChangeMessageVisibilityEndpointParamsInterceptor;

impl ::aws_smithy_runtime_api::client::interceptors::Intercept for ChangeMessageVisibilityEndpointParamsInterceptor {
    fn name(&self) -> &'static str {
        "ChangeMessageVisibilityEndpointParamsInterceptor"
    }

    fn read_before_execution(
        &self,
        context: &::aws_smithy_runtime_api::client::interceptors::context::BeforeSerializationInterceptorContextRef<
            '_,
            ::aws_smithy_runtime_api::client::interceptors::context::Input,
            ::aws_smithy_runtime_api::client::interceptors::context::Output,
            ::aws_smithy_runtime_api::client::interceptors::context::Error,
        >,
        cfg: &mut ::aws_smithy_types::config_bag::ConfigBag,
    ) -> ::std::result::Result<(), ::aws_smithy_runtime_api::box_error::BoxError> {
        let _input = context
            .input()
            .downcast_ref::<ChangeMessageVisibilityInput>()
            .ok_or("failed to downcast to ChangeMessageVisibilityInput")?;

        let params = crate::config::endpoint::Params::builder()
            .set_region(cfg.load::<::aws_types::region::Region>().map(|r| r.as_ref().to_owned()))
            .set_use_dual_stack(cfg.load::<::aws_types::endpoint_config::UseDualStack>().map(|ty| ty.0))
            .set_use_fips(cfg.load::<::aws_types::endpoint_config::UseFips>().map(|ty| ty.0))
            .set_endpoint(cfg.load::<::aws_types::endpoint_config::EndpointUrl>().map(|ty| ty.0.clone()))
            .build()
            .map_err(|err| {
                ::aws_smithy_runtime_api::client::interceptors::error::ContextAttachedError::new("endpoint params could not be built", err)
            })?;
        cfg.interceptor_state()
            .store_put(::aws_smithy_runtime_api::client::endpoint::EndpointResolverParams::new(params));
        ::std::result::Result::Ok(())
    }
}

/// Error type for the `ChangeMessageVisibilityError` operation.
#[non_exhaustive]
#[derive(::std::fmt::Debug)]
pub enum ChangeMessageVisibilityError {
    /// <p>The <code>accountId</code> is invalid.</p>
    InvalidAddress(crate::types::error::InvalidAddress),
    /// <p>When the request to a queue is not HTTPS and SigV4.</p>
    InvalidSecurity(crate::types::error::InvalidSecurity),
    /// <p>The specified message isn't in flight.</p>
    MessageNotInflight(crate::types::error::MessageNotInflight),
    /// <p>The specified queue doesn't exist.</p>
    QueueDoesNotExist(crate::types::error::QueueDoesNotExist),
    /// <p>The specified receipt handle isn't valid.</p>
    ReceiptHandleIsInvalid(crate::types::error::ReceiptHandleIsInvalid),
    /// <p>The request was denied due to request throttling.</p>
    /// <ul>
    /// <li> <p>The rate of requests per second exceeds the Amazon Web Services KMS request quota for an account and Region. </p> </li>
    /// <li> <p>A burst or sustained high rate of requests to change the state of the same KMS key. This condition is often known as a "hot key."</p> </li>
    /// <li> <p>Requests for operations on KMS keys in a Amazon Web Services CloudHSM key store might be throttled at a lower-than-expected rate when the Amazon Web Services CloudHSM cluster associated with the Amazon Web Services CloudHSM key store is processing numerous commands, including those unrelated to the Amazon Web Services CloudHSM key store.</p> </li>
    /// </ul>
    RequestThrottled(crate::types::error::RequestThrottled),
    /// <p>Error code 400. Unsupported operation.</p>
    UnsupportedOperation(crate::types::error::UnsupportedOperation),
    /// An unexpected error occurred (e.g., invalid JSON returned by the service or an unknown error code).
    #[deprecated(note = "Matching `Unhandled` directly is not forwards compatible. Instead, match using a \
    variable wildcard pattern and check `.code()`:
     \
    &nbsp;&nbsp;&nbsp;`err if err.code() == Some(\"SpecificExceptionCode\") => { /* handle the error */ }`
     \
    See [`ProvideErrorMetadata`](#impl-ProvideErrorMetadata-for-ChangeMessageVisibilityError) for what information is available for the error.")]
    Unhandled(crate::error::sealed_unhandled::Unhandled),
}
impl ChangeMessageVisibilityError {
    /// Creates the `ChangeMessageVisibilityError::Unhandled` variant from any error type.
    pub fn unhandled(
        err: impl ::std::convert::Into<::std::boxed::Box<dyn ::std::error::Error + ::std::marker::Send + ::std::marker::Sync + 'static>>,
    ) -> Self {
        Self::Unhandled(crate::error::sealed_unhandled::Unhandled {
            source: err.into(),
            meta: ::std::default::Default::default(),
        })
    }

    /// Creates the `ChangeMessageVisibilityError::Unhandled` variant from an [`ErrorMetadata`](::aws_smithy_types::error::ErrorMetadata).
    pub fn generic(err: ::aws_smithy_types::error::ErrorMetadata) -> Self {
        Self::Unhandled(crate::error::sealed_unhandled::Unhandled {
            source: err.clone().into(),
            meta: err,
        })
    }
    ///
    /// Returns error metadata, which includes the error code, message,
    /// request ID, and potentially additional information.
    ///
    pub fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        match self {
            Self::InvalidAddress(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::InvalidSecurity(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::MessageNotInflight(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::QueueDoesNotExist(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::ReceiptHandleIsInvalid(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::RequestThrottled(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::UnsupportedOperation(e) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(e),
            Self::Unhandled(e) => &e.meta,
        }
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::InvalidAddress`.
    pub fn is_invalid_address(&self) -> bool {
        matches!(self, Self::InvalidAddress(_))
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::InvalidSecurity`.
    pub fn is_invalid_security(&self) -> bool {
        matches!(self, Self::InvalidSecurity(_))
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::MessageNotInflight`.
    pub fn is_message_not_inflight(&self) -> bool {
        matches!(self, Self::MessageNotInflight(_))
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::QueueDoesNotExist`.
    pub fn is_queue_does_not_exist(&self) -> bool {
        matches!(self, Self::QueueDoesNotExist(_))
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::ReceiptHandleIsInvalid`.
    pub fn is_receipt_handle_is_invalid(&self) -> bool {
        matches!(self, Self::ReceiptHandleIsInvalid(_))
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::RequestThrottled`.
    pub fn is_request_throttled(&self) -> bool {
        matches!(self, Self::RequestThrottled(_))
    }
    /// Returns `true` if the error kind is `ChangeMessageVisibilityError::UnsupportedOperation`.
    pub fn is_unsupported_operation(&self) -> bool {
        matches!(self, Self::UnsupportedOperation(_))
    }
}
impl ::std::error::Error for ChangeMessageVisibilityError {
    fn source(&self) -> ::std::option::Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Self::InvalidAddress(_inner) => ::std::option::Option::Some(_inner),
            Self::InvalidSecurity(_inner) => ::std::option::Option::Some(_inner),
            Self::MessageNotInflight(_inner) => ::std::option::Option::Some(_inner),
            Self::QueueDoesNotExist(_inner) => ::std::option::Option::Some(_inner),
            Self::ReceiptHandleIsInvalid(_inner) => ::std::option::Option::Some(_inner),
            Self::RequestThrottled(_inner) => ::std::option::Option::Some(_inner),
            Self::UnsupportedOperation(_inner) => ::std::option::Option::Some(_inner),
            Self::Unhandled(_inner) => ::std::option::Option::Some(&*_inner.source),
        }
    }
}
impl ::std::fmt::Display for ChangeMessageVisibilityError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            Self::InvalidAddress(_inner) => _inner.fmt(f),
            Self::InvalidSecurity(_inner) => _inner.fmt(f),
            Self::MessageNotInflight(_inner) => _inner.fmt(f),
            Self::QueueDoesNotExist(_inner) => _inner.fmt(f),
            Self::ReceiptHandleIsInvalid(_inner) => _inner.fmt(f),
            Self::RequestThrottled(_inner) => _inner.fmt(f),
            Self::UnsupportedOperation(_inner) => _inner.fmt(f),
            Self::Unhandled(_inner) => {
                if let ::std::option::Option::Some(code) = ::aws_smithy_types::error::metadata::ProvideErrorMetadata::code(self) {
                    write!(f, "unhandled error ({code})")
                } else {
                    f.write_str("unhandled error")
                }
            }
        }
    }
}
impl ::aws_smithy_types::retry::ProvideErrorKind for ChangeMessageVisibilityError {
    fn code(&self) -> ::std::option::Option<&str> {
        ::aws_smithy_types::error::metadata::ProvideErrorMetadata::code(self)
    }
    fn retryable_error_kind(&self) -> ::std::option::Option<::aws_smithy_types::retry::ErrorKind> {
        ::std::option::Option::None
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ChangeMessageVisibilityError {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        match self {
            Self::InvalidAddress(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::InvalidSecurity(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::MessageNotInflight(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::QueueDoesNotExist(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::ReceiptHandleIsInvalid(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::RequestThrottled(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::UnsupportedOperation(_inner) => ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(_inner),
            Self::Unhandled(_inner) => &_inner.meta,
        }
    }
}
impl ::aws_smithy_runtime_api::client::result::CreateUnhandledError for ChangeMessageVisibilityError {
    fn create_unhandled_error(
        source: ::std::boxed::Box<dyn ::std::error::Error + ::std::marker::Send + ::std::marker::Sync + 'static>,
        meta: ::std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
    ) -> Self {
        Self::Unhandled(crate::error::sealed_unhandled::Unhandled {
            source,
            meta: meta.unwrap_or_default(),
        })
    }
}
impl ::aws_types::request_id::RequestId for crate::operation::change_message_visibility::ChangeMessageVisibilityError {
    fn request_id(&self) -> Option<&str> {
        self.meta().request_id()
    }
}

pub use crate::operation::change_message_visibility::_change_message_visibility_output::ChangeMessageVisibilityOutput;

pub use crate::operation::change_message_visibility::_change_message_visibility_input::ChangeMessageVisibilityInput;

mod _change_message_visibility_input;

mod _change_message_visibility_output;

/// Builders
pub mod builders;