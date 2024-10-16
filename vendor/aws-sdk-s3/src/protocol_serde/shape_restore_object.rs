// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_restore_object_http_error(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<crate::operation::restore_object::RestoreObjectOutput, crate::operation::restore_object::RestoreObjectError> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::restore_object::RestoreObjectError::unhandled)?;
    generic_builder = crate::s3_request_id::apply_extended_request_id(generic_builder, _response_headers);
    generic_builder = ::aws_types::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    let error_code = match generic.code() {
        Some(code) => code,
        None => return Err(crate::operation::restore_object::RestoreObjectError::unhandled(generic)),
    };

    let _error_message = generic.message().map(|msg| msg.to_owned());
    Err(match error_code {
        "ObjectAlreadyInActiveTierError" => crate::operation::restore_object::RestoreObjectError::ObjectAlreadyInActiveTierError({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ObjectAlreadyInActiveTierErrorBuilder::default();
                output = crate::protocol_serde::shape_object_already_in_active_tier_error::de_object_already_in_active_tier_error_xml_err(
                    _response_body,
                    output,
                )
                .map_err(crate::operation::restore_object::RestoreObjectError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        _ => crate::operation::restore_object::RestoreObjectError::generic(generic),
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_restore_object_http_response(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<crate::operation::restore_object::RestoreObjectOutput, crate::operation::restore_object::RestoreObjectError> {
    Ok({
        #[allow(unused_mut)]
        let mut output = crate::operation::restore_object::builders::RestoreObjectOutputBuilder::default();
        output = output.set_request_charged(
            crate::protocol_serde::shape_restore_object_output::de_request_charged_header(_response_headers).map_err(|_| {
                crate::operation::restore_object::RestoreObjectError::unhandled("Failed to parse RequestCharged from header `x-amz-request-charged")
            })?,
        );
        output = output.set_restore_output_path(
            crate::protocol_serde::shape_restore_object_output::de_restore_output_path_header(_response_headers).map_err(|_| {
                crate::operation::restore_object::RestoreObjectError::unhandled(
                    "Failed to parse RestoreOutputPath from header `x-amz-restore-output-path",
                )
            })?,
        );
        output._set_extended_request_id(crate::s3_request_id::RequestIdExt::extended_request_id(_response_headers).map(str::to_string));
        output._set_request_id(::aws_types::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        output.build()
    })
}

pub fn ser_restore_object_headers(
    input: &crate::operation::restore_object::RestoreObjectInput,
    mut builder: ::http::request::Builder,
) -> std::result::Result<::http::request::Builder, ::aws_smithy_types::error::operation::BuildError> {
    if let ::std::option::Option::Some(inner_1) = &input.request_payer {
        let formatted_2 = inner_1.as_str();
        if !formatted_2.is_empty() {
            let header_value = formatted_2;
            let header_value: ::http::HeaderValue = header_value.parse().map_err(|err| {
                ::aws_smithy_types::error::operation::BuildError::invalid_field(
                    "request_payer",
                    format!("`{}` cannot be used as a header value: {}", &header_value, err),
                )
            })?;
            builder = builder.header("x-amz-request-payer", header_value);
        }
    }
    if let ::std::option::Option::Some(inner_3) = &input.checksum_algorithm {
        let formatted_4 = inner_3.as_str();
        if !formatted_4.is_empty() {
            let header_value = formatted_4;
            let header_value: ::http::HeaderValue = header_value.parse().map_err(|err| {
                ::aws_smithy_types::error::operation::BuildError::invalid_field(
                    "checksum_algorithm",
                    format!("`{}` cannot be used as a header value: {}", &header_value, err),
                )
            })?;
            builder = builder.header("x-amz-sdk-checksum-algorithm", header_value);
        }
    }
    if let ::std::option::Option::Some(inner_5) = &input.expected_bucket_owner {
        let formatted_6 = inner_5.as_str();
        if !formatted_6.is_empty() {
            let header_value = formatted_6;
            let header_value: ::http::HeaderValue = header_value.parse().map_err(|err| {
                ::aws_smithy_types::error::operation::BuildError::invalid_field(
                    "expected_bucket_owner",
                    format!("`{}` cannot be used as a header value: {}", &header_value, err),
                )
            })?;
            builder = builder.header("x-amz-expected-bucket-owner", header_value);
        }
    }
    Ok(builder)
}