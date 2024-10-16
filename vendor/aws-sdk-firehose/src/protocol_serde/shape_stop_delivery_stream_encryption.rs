// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_stop_delivery_stream_encryption_http_error(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput,
    crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError,
> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::unhandled)?;
    generic_builder = ::aws_types::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    let error_code = match generic.code() {
        Some(code) => code,
        None => return Err(crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::unhandled(generic)),
    };

    let _error_message = generic.message().map(|msg| msg.to_owned());
    Err(match error_code {
        "InvalidArgumentException" => {
            crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::InvalidArgumentException({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::InvalidArgumentExceptionBuilder::default();
                    output = crate::protocol_serde::shape_invalid_argument_exception::de_invalid_argument_exception_json_err(_response_body, output)
                        .map_err(crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        "LimitExceededException" => crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::LimitExceededException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::LimitExceededExceptionBuilder::default();
                output = crate::protocol_serde::shape_limit_exceeded_exception::de_limit_exceeded_exception_json_err(_response_body, output)
                    .map_err(crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ResourceInUseException" => crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::ResourceInUseException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ResourceInUseExceptionBuilder::default();
                output = crate::protocol_serde::shape_resource_in_use_exception::de_resource_in_use_exception_json_err(_response_body, output)
                    .map_err(crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ResourceNotFoundException" => {
            crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::ResourceNotFoundException({
                #[allow(unused_mut)]
                let mut tmp = {
                    #[allow(unused_mut)]
                    let mut output = crate::types::error::builders::ResourceNotFoundExceptionBuilder::default();
                    output =
                        crate::protocol_serde::shape_resource_not_found_exception::de_resource_not_found_exception_json_err(_response_body, output)
                            .map_err(crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::unhandled)?;
                    let output = output.meta(generic);
                    output.build()
                };
                if tmp.message.is_none() {
                    tmp.message = _error_message;
                }
                tmp
            })
        }
        _ => crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError::generic(generic),
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_stop_delivery_stream_encryption_http_response(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionOutput,
    crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionError,
> {
    Ok({
        #[allow(unused_mut)]
        let mut output = crate::operation::stop_delivery_stream_encryption::builders::StopDeliveryStreamEncryptionOutputBuilder::default();
        output._set_request_id(::aws_types::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        output.build()
    })
}

pub fn ser_stop_delivery_stream_encryption_input(
    input: &crate::operation::stop_delivery_stream_encryption::StopDeliveryStreamEncryptionInput,
) -> Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    let mut object = ::aws_smithy_json::serialize::JsonObjectWriter::new(&mut out);
    crate::protocol_serde::shape_stop_delivery_stream_encryption_input::ser_stop_delivery_stream_encryption_input_input(&mut object, input)?;
    object.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}