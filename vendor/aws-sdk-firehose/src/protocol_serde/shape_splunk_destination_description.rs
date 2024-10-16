// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub(crate) fn de_splunk_destination_description<'a, I>(
    tokens: &mut ::std::iter::Peekable<I>,
) -> Result<Option<crate::types::SplunkDestinationDescription>, ::aws_smithy_json::deserialize::error::DeserializeError>
where
    I: Iterator<Item = Result<::aws_smithy_json::deserialize::Token<'a>, ::aws_smithy_json::deserialize::error::DeserializeError>>,
{
    match tokens.next().transpose()? {
        Some(::aws_smithy_json::deserialize::Token::ValueNull { .. }) => Ok(None),
        Some(::aws_smithy_json::deserialize::Token::StartObject { .. }) => {
            #[allow(unused_mut)]
            let mut builder = crate::types::builders::SplunkDestinationDescriptionBuilder::default();
            loop {
                match tokens.next().transpose()? {
                    Some(::aws_smithy_json::deserialize::Token::EndObject { .. }) => break,
                    Some(::aws_smithy_json::deserialize::Token::ObjectKey { key, .. }) => match key.to_unescaped()?.as_ref() {
                        "HECEndpoint" => {
                            builder = builder.set_hec_endpoint(
                                ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                                    .map(|s| s.to_unescaped().map(|u| u.into_owned()))
                                    .transpose()?,
                            );
                        }
                        "HECEndpointType" => {
                            builder = builder.set_hec_endpoint_type(
                                ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                                    .map(|s| s.to_unescaped().map(|u| crate::types::HecEndpointType::from(u.as_ref())))
                                    .transpose()?,
                            );
                        }
                        "HECToken" => {
                            builder = builder.set_hec_token(
                                ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                                    .map(|s| s.to_unescaped().map(|u| u.into_owned()))
                                    .transpose()?,
                            );
                        }
                        "HECAcknowledgmentTimeoutInSeconds" => {
                            builder = builder.set_hec_acknowledgment_timeout_in_seconds(
                                ::aws_smithy_json::deserialize::token::expect_number_or_null(tokens.next())?
                                    .map(i32::try_from)
                                    .transpose()?,
                            );
                        }
                        "RetryOptions" => {
                            builder = builder.set_retry_options(crate::protocol_serde::shape_splunk_retry_options::de_splunk_retry_options(tokens)?);
                        }
                        "S3BackupMode" => {
                            builder = builder.set_s3_backup_mode(
                                ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                                    .map(|s| s.to_unescaped().map(|u| crate::types::SplunkS3BackupMode::from(u.as_ref())))
                                    .transpose()?,
                            );
                        }
                        "S3DestinationDescription" => {
                            builder = builder.set_s3_destination_description(
                                crate::protocol_serde::shape_s3_destination_description::de_s3_destination_description(tokens)?,
                            );
                        }
                        "ProcessingConfiguration" => {
                            builder = builder.set_processing_configuration(
                                crate::protocol_serde::shape_processing_configuration::de_processing_configuration(tokens)?,
                            );
                        }
                        "CloudWatchLoggingOptions" => {
                            builder = builder.set_cloud_watch_logging_options(
                                crate::protocol_serde::shape_cloud_watch_logging_options::de_cloud_watch_logging_options(tokens)?,
                            );
                        }
                        _ => ::aws_smithy_json::deserialize::token::skip_value(tokens)?,
                    },
                    other => {
                        return Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(format!(
                            "expected object key or end object, found: {:?}",
                            other
                        )))
                    }
                }
            }
            Ok(Some(builder.build()))
        }
        _ => Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(
            "expected start object or null",
        )),
    }
}