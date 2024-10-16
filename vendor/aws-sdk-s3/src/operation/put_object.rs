// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
/// Orchestration and serialization glue logic for `PutObject`.
#[derive(::std::clone::Clone, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutObject;
impl PutObject {
    /// Creates a new `PutObject`
    pub fn new() -> Self {
        Self
    }
    pub(crate) async fn orchestrate(
        runtime_plugins: &::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
        input: crate::operation::put_object::PutObjectInput,
    ) -> ::std::result::Result<
        crate::operation::put_object::PutObjectOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::put_object::PutObjectError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let map_err = |err: ::aws_smithy_runtime_api::client::result::SdkError<
            ::aws_smithy_runtime_api::client::interceptors::context::Error,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >| {
            err.map_service_error(|err| {
                err.downcast::<crate::operation::put_object::PutObjectError>()
                    .expect("correct error type")
            })
        };
        let context = Self::orchestrate_with_stop_point(runtime_plugins, input, ::aws_smithy_runtime::client::orchestrator::StopPoint::None)
            .await
            .map_err(map_err)?;
        let output = context.finalize().map_err(map_err)?;
        ::std::result::Result::Ok(
            output
                .downcast::<crate::operation::put_object::PutObjectOutput>()
                .expect("correct output type"),
        )
    }

    pub(crate) async fn orchestrate_with_stop_point(
        runtime_plugins: &::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
        input: crate::operation::put_object::PutObjectInput,
        stop_point: ::aws_smithy_runtime::client::orchestrator::StopPoint,
    ) -> ::std::result::Result<
        ::aws_smithy_runtime_api::client::interceptors::context::InterceptorContext,
        ::aws_smithy_runtime_api::client::result::SdkError<
            ::aws_smithy_runtime_api::client::interceptors::context::Error,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = ::aws_smithy_runtime_api::client::interceptors::context::Input::erase(input);
        ::aws_smithy_runtime::client::orchestrator::invoke_with_stop_point("s3", "PutObject", input, runtime_plugins, stop_point).await
    }

    pub(crate) fn operation_runtime_plugins(
        client_runtime_plugins: ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
        client_config: &crate::config::Config,
        config_override: ::std::option::Option<crate::config::Builder>,
    ) -> ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins {
        let mut runtime_plugins = client_runtime_plugins.with_operation_plugin(Self::new());
        runtime_plugins = runtime_plugins.with_client_plugin(crate::auth_plugin::DefaultAuthOptionsPlugin::new(vec![
            ::aws_runtime::auth::sigv4::SCHEME_ID,
            #[cfg(feature = "sigv4a")]
            {
                ::aws_runtime::auth::sigv4a::SCHEME_ID
            },
            ::aws_smithy_runtime::client::auth::no_auth::NO_AUTH_SCHEME_ID,
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
impl ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugin for PutObject {
    fn config(&self) -> ::std::option::Option<::aws_smithy_types::config_bag::FrozenLayer> {
        let mut cfg = ::aws_smithy_types::config_bag::Layer::new("PutObject");

        cfg.store_put(::aws_smithy_runtime_api::client::ser_de::SharedRequestSerializer::new(
            PutObjectRequestSerializer,
        ));
        cfg.store_put(::aws_smithy_runtime_api::client::ser_de::SharedResponseDeserializer::new(
            PutObjectResponseDeserializer,
        ));

        cfg.store_put(::aws_smithy_runtime_api::client::auth::AuthSchemeOptionResolverParams::new(
            ::aws_smithy_runtime_api::client::auth::static_resolver::StaticAuthSchemeOptionResolverParams::new(),
        ));

        cfg.store_put(::aws_smithy_runtime_api::client::orchestrator::SensitiveOutput);
        cfg.store_put(::aws_smithy_http::operation::Metadata::new("PutObject", "s3"));
        let mut signing_options = ::aws_runtime::auth::SigningOptions::default();
        signing_options.double_uri_encode = false;
        signing_options.content_sha256_header = true;
        signing_options.normalize_uri_path = false;
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
        let mut rcb = ::aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder::new("PutObject")
            .with_interceptor(
                ::aws_smithy_runtime::client::stalled_stream_protection::StalledStreamProtectionInterceptor::new(
                    ::aws_smithy_runtime::client::stalled_stream_protection::StalledStreamProtectionInterceptorKind::ResponseBody,
                ),
            )
            .with_interceptor(PutObjectEndpointParamsInterceptor)
            .with_interceptor(crate::http_request_checksum::RequestChecksumInterceptor::new(
                |input: &::aws_smithy_runtime_api::client::interceptors::context::Input| {
                    let input: &crate::operation::put_object::PutObjectInput = input.downcast_ref().expect("correct type");
                    let checksum_algorithm = input.checksum_algorithm();
                    let checksum_algorithm = checksum_algorithm.map(|algorithm| algorithm.as_str());
                    let checksum_algorithm = match checksum_algorithm {
                        Some(algo) => Some(
                            algo.parse::<::aws_smithy_checksums::ChecksumAlgorithm>()
                                .map_err(::aws_smithy_types::error::operation::BuildError::other)?,
                        ),
                        None => None,
                    };
                    ::std::result::Result::<_, ::aws_smithy_runtime_api::box_error::BoxError>::Ok(checksum_algorithm)
                },
            ))
            .with_retry_classifier(::aws_smithy_runtime::client::retries::classifiers::TransientErrorClassifier::<
                crate::operation::put_object::PutObjectError,
            >::new())
            .with_retry_classifier(::aws_smithy_runtime::client::retries::classifiers::ModeledAsRetryableClassifier::<
                crate::operation::put_object::PutObjectError,
            >::new())
            .with_retry_classifier(::aws_runtime::retries::classifiers::AwsErrorCodeClassifier::<
                crate::operation::put_object::PutObjectError,
            >::new());

        ::std::borrow::Cow::Owned(rcb)
    }
}

#[derive(Debug)]
struct PutObjectResponseDeserializer;
impl ::aws_smithy_runtime_api::client::ser_de::DeserializeResponse for PutObjectResponseDeserializer {
    fn deserialize_nonstreaming(
        &self,
        response: &::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    ) -> ::aws_smithy_runtime_api::client::interceptors::context::OutputOrError {
        let (success, status) = (response.status().is_success(), response.status().as_u16());
        let headers = response.headers();
        let body = response.body().bytes().expect("body loaded");
        #[allow(unused_mut)]
        let mut force_error = false;
        ::tracing::debug!(extended_request_id = ?crate::s3_request_id::RequestIdExt::extended_request_id(response));
        if matches!(crate::rest_xml_unwrapped_errors::body_is_error(body), Ok(true)) {
            force_error = true;
        }
        ::tracing::debug!(request_id = ?::aws_types::request_id::RequestId::request_id(response));
        let parse_result = if !success && status != 200 || force_error {
            crate::protocol_serde::shape_put_object::de_put_object_http_error(status, headers, body)
        } else {
            crate::protocol_serde::shape_put_object::de_put_object_http_response(status, headers, body)
        };
        crate::protocol_serde::type_erase_result(parse_result)
    }
}
#[derive(Debug)]
struct PutObjectRequestSerializer;
impl ::aws_smithy_runtime_api::client::ser_de::SerializeRequest for PutObjectRequestSerializer {
    #[allow(unused_mut, clippy::let_and_return, clippy::needless_borrow, clippy::useless_conversion)]
    fn serialize_input(
        &self,
        input: ::aws_smithy_runtime_api::client::interceptors::context::Input,
        _cfg: &mut ::aws_smithy_types::config_bag::ConfigBag,
    ) -> ::std::result::Result<::aws_smithy_runtime_api::client::orchestrator::HttpRequest, ::aws_smithy_runtime_api::box_error::BoxError> {
        let input = input.downcast::<crate::operation::put_object::PutObjectInput>().expect("correct type");
        let _header_serialization_settings = _cfg
            .load::<crate::serialization_settings::HeaderSerializationSettings>()
            .cloned()
            .unwrap_or_default();
        let mut request_builder = {
            fn uri_base(
                _input: &crate::operation::put_object::PutObjectInput,
                output: &mut ::std::string::String,
            ) -> ::std::result::Result<(), ::aws_smithy_types::error::operation::BuildError> {
                use ::std::fmt::Write as _;
                let input_1 = &_input.key;
                let input_1 = input_1
                    .as_ref()
                    .ok_or_else(|| ::aws_smithy_types::error::operation::BuildError::missing_field("key", "cannot be empty or unset"))?;
                let key = ::aws_smithy_http::label::fmt_string(input_1, ::aws_smithy_http::label::EncodingStrategy::Greedy);
                if key.is_empty() {
                    return ::std::result::Result::Err(::aws_smithy_types::error::operation::BuildError::missing_field(
                        "key",
                        "cannot be empty or unset",
                    ));
                }
                ::std::write!(output, "/{Key}", Key = key).expect("formatting should succeed");
                ::std::result::Result::Ok(())
            }
            fn uri_query(
                _input: &crate::operation::put_object::PutObjectInput,
                mut output: &mut ::std::string::String,
            ) -> ::std::result::Result<(), ::aws_smithy_types::error::operation::BuildError> {
                let mut query = ::aws_smithy_http::query::Writer::new(output);
                query.push_kv("x-id", "PutObject");
                ::std::result::Result::Ok(())
            }
            #[allow(clippy::unnecessary_wraps)]
            fn update_http_builder(
                input: &crate::operation::put_object::PutObjectInput,
                builder: ::http::request::Builder,
            ) -> ::std::result::Result<::http::request::Builder, ::aws_smithy_types::error::operation::BuildError> {
                let mut uri = ::std::string::String::new();
                uri_base(input, &mut uri)?;
                uri_query(input, &mut uri)?;
                let builder = crate::protocol_serde::shape_put_object::ser_put_object_headers(input, builder)?;
                ::std::result::Result::Ok(builder.method("PUT").uri(uri))
            }
            let mut builder = update_http_builder(&input, ::http::request::Builder::new())?;
            builder = _header_serialization_settings.set_default_header(builder, ::http::header::CONTENT_TYPE, "application/octet-stream");
            builder
        };
        let body = crate::protocol_serde::shape_put_object_input::ser_body_http_payload(input.body)?.into_inner();
        if let Some(content_length) = body.content_length() {
            let content_length = content_length.to_string();
            request_builder = _header_serialization_settings.set_default_header(request_builder, ::http::header::CONTENT_LENGTH, &content_length);
        }
        ::std::result::Result::Ok(request_builder.body(body).expect("valid request").try_into().unwrap())
    }
}
#[derive(Debug)]
struct PutObjectEndpointParamsInterceptor;

impl ::aws_smithy_runtime_api::client::interceptors::Intercept for PutObjectEndpointParamsInterceptor {
    fn name(&self) -> &'static str {
        "PutObjectEndpointParamsInterceptor"
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
            .downcast_ref::<PutObjectInput>()
            .ok_or("failed to downcast to PutObjectInput")?;

        let params = crate::config::endpoint::Params::builder()
            .set_region(cfg.load::<::aws_types::region::Region>().map(|r| r.as_ref().to_owned()))
            .set_use_fips(cfg.load::<::aws_types::endpoint_config::UseFips>().map(|ty| ty.0))
            .set_use_dual_stack(cfg.load::<::aws_types::endpoint_config::UseDualStack>().map(|ty| ty.0))
            .set_endpoint(cfg.load::<::aws_types::endpoint_config::EndpointUrl>().map(|ty| ty.0.clone()))
            .set_force_path_style(cfg.load::<crate::config::ForcePathStyle>().map(|ty| ty.0))
            .set_use_arn_region(cfg.load::<crate::config::UseArnRegion>().map(|ty| ty.0))
            .set_disable_multi_region_access_points(cfg.load::<crate::config::DisableMultiRegionAccessPoints>().map(|ty| ty.0))
            .set_accelerate(cfg.load::<crate::config::Accelerate>().map(|ty| ty.0))
            .set_disable_s3_express_session_auth(cfg.load::<crate::config::DisableS3ExpressSessionAuth>().map(|ty| ty.0))
            .set_bucket(Some(
                _input
                    .bucket
                    .clone()
                    .filter(|f| !AsRef::<str>::as_ref(f).trim().is_empty())
                    .ok_or_else(|| ::aws_smithy_types::error::operation::BuildError::missing_field("bucket", "A required field was not set"))?,
            ))
            .set_key(Some(
                _input
                    .key
                    .clone()
                    .filter(|f| !AsRef::<str>::as_ref(f).trim().is_empty())
                    .ok_or_else(|| ::aws_smithy_types::error::operation::BuildError::missing_field("key", "A required field was not set"))?,
            ))
            .build()
            .map_err(|err| {
                ::aws_smithy_runtime_api::client::interceptors::error::ContextAttachedError::new("endpoint params could not be built", err)
            })?;
        cfg.interceptor_state()
            .store_put(::aws_smithy_runtime_api::client::endpoint::EndpointResolverParams::new(params));
        ::std::result::Result::Ok(())
    }
}
#[allow(unreachable_code, unused_variables)]
#[cfg(test)]
mod put_object_request_test {
    /// This test validates that if a content-type is specified, that only one content-type header is sent
    /// Test ID: DontSendDuplicateContentType
    #[::tokio::test]
    #[allow(unused_mut)]
    async fn dont_send_duplicate_content_type_request() {
        let (http_client, request_receiver) = ::aws_smithy_runtime::client::http::test_util::capture_request(None);
        let config_builder = crate::config::Config::builder().with_test_defaults().endpoint_url("https://example.com");
        let config_builder = config_builder.region(::aws_types::region::Region::new("us-east-1"));
        let mut config_builder = config_builder;
        config_builder.set_region(Some(crate::config::Region::new("us-east-1")));

        let config = config_builder.http_client(http_client).build();
        let client = crate::Client::from_conf(config);
        let result = client
            .put_object()
            .set_bucket(::std::option::Option::Some("test-bucket".to_owned()))
            .set_key(::std::option::Option::Some("test-key".to_owned()))
            .set_content_type(::std::option::Option::Some("text/html".to_owned()))
            .send()
            .await;
        let _ = dbg!(result);
        let http_request = request_receiver.expect_request();
        let expected_headers = [("content-type", "text/html")];
        ::aws_smithy_protocol_test::assert_ok(::aws_smithy_protocol_test::validate_headers(http_request.headers(), expected_headers));
        let uri: ::http::Uri = http_request.uri().parse().expect("invalid URI sent");
        ::pretty_assertions::assert_eq!(http_request.method(), "PUT", "method was incorrect");
        ::pretty_assertions::assert_eq!(uri.path(), "/test-key", "path was incorrect");
    }
    /// This test validates that if a content-length is specified, that only one content-length header is sent
    /// Test ID: DontSendDuplicateContentLength
    #[::tokio::test]
    #[allow(unused_mut)]
    async fn dont_send_duplicate_content_length_request() {
        let (http_client, request_receiver) = ::aws_smithy_runtime::client::http::test_util::capture_request(None);
        let config_builder = crate::config::Config::builder().with_test_defaults().endpoint_url("https://example.com");
        let config_builder = config_builder.region(::aws_types::region::Region::new("us-east-1"));
        let mut config_builder = config_builder;
        config_builder.set_region(Some(crate::config::Region::new("us-east-1")));

        let config = config_builder.http_client(http_client).build();
        let client = crate::Client::from_conf(config);
        let result = client
            .put_object()
            .set_bucket(::std::option::Option::Some("test-bucket".to_owned()))
            .set_key(::std::option::Option::Some("test-key".to_owned()))
            .set_content_length(::std::option::Option::Some(2))
            .set_body(::std::option::Option::Some(::aws_smithy_types::byte_stream::ByteStream::from_static(
                b"ab",
            )))
            .send()
            .await;
        let _ = dbg!(result);
        let http_request = request_receiver.expect_request();
        let expected_headers = [("content-length", "2")];
        ::aws_smithy_protocol_test::assert_ok(::aws_smithy_protocol_test::validate_headers(http_request.headers(), expected_headers));
        let uri: ::http::Uri = http_request.uri().parse().expect("invalid URI sent");
        ::pretty_assertions::assert_eq!(http_request.method(), "PUT", "method was incorrect");
        ::pretty_assertions::assert_eq!(uri.path(), "/test-key", "path was incorrect");
    }
}

/// Error type for the `PutObjectError` operation.
#[non_exhaustive]
#[derive(::std::fmt::Debug)]
pub enum PutObjectError {
    /// An unexpected error occurred (e.g., invalid JSON returned by the service or an unknown error code).
    #[deprecated(note = "Matching `Unhandled` directly is not forwards compatible. Instead, match using a \
    variable wildcard pattern and check `.code()`:
     \
    &nbsp;&nbsp;&nbsp;`err if err.code() == Some(\"SpecificExceptionCode\") => { /* handle the error */ }`
     \
    See [`ProvideErrorMetadata`](#impl-ProvideErrorMetadata-for-PutObjectError) for what information is available for the error.")]
    Unhandled(crate::error::sealed_unhandled::Unhandled),
}
impl PutObjectError {
    /// Creates the `PutObjectError::Unhandled` variant from any error type.
    pub fn unhandled(
        err: impl ::std::convert::Into<::std::boxed::Box<dyn ::std::error::Error + ::std::marker::Send + ::std::marker::Sync + 'static>>,
    ) -> Self {
        Self::Unhandled(crate::error::sealed_unhandled::Unhandled {
            source: err.into(),
            meta: ::std::default::Default::default(),
        })
    }

    /// Creates the `PutObjectError::Unhandled` variant from an [`ErrorMetadata`](::aws_smithy_types::error::ErrorMetadata).
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
            Self::Unhandled(e) => &e.meta,
        }
    }
}
impl ::std::error::Error for PutObjectError {
    fn source(&self) -> ::std::option::Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Self::Unhandled(_inner) => ::std::option::Option::Some(&*_inner.source),
        }
    }
}
impl ::std::fmt::Display for PutObjectError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
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
impl ::aws_smithy_types::retry::ProvideErrorKind for PutObjectError {
    fn code(&self) -> ::std::option::Option<&str> {
        ::aws_smithy_types::error::metadata::ProvideErrorMetadata::code(self)
    }
    fn retryable_error_kind(&self) -> ::std::option::Option<::aws_smithy_types::retry::ErrorKind> {
        ::std::option::Option::None
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for PutObjectError {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        match self {
            Self::Unhandled(_inner) => &_inner.meta,
        }
    }
}
impl ::aws_smithy_runtime_api::client::result::CreateUnhandledError for PutObjectError {
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
impl crate::s3_request_id::RequestIdExt for crate::operation::put_object::PutObjectError {
    fn extended_request_id(&self) -> Option<&str> {
        self.meta().extended_request_id()
    }
}
impl ::aws_types::request_id::RequestId for crate::operation::put_object::PutObjectError {
    fn request_id(&self) -> Option<&str> {
        self.meta().request_id()
    }
}

pub use crate::operation::put_object::_put_object_output::PutObjectOutput;

pub use crate::operation::put_object::_put_object_input::PutObjectInput;

mod _put_object_input;

mod _put_object_output;

/// Builders
pub mod builders;