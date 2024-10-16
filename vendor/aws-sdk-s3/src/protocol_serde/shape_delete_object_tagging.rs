// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_delete_object_tagging_http_error(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::delete_object_tagging::DeleteObjectTaggingOutput,
    crate::operation::delete_object_tagging::DeleteObjectTaggingError,
> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::delete_object_tagging::DeleteObjectTaggingError::unhandled)?;
    generic_builder = crate::s3_request_id::apply_extended_request_id(generic_builder, _response_headers);
    generic_builder = ::aws_types::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    Err(crate::operation::delete_object_tagging::DeleteObjectTaggingError::generic(generic))
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_delete_object_tagging_http_response(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::delete_object_tagging::DeleteObjectTaggingOutput,
    crate::operation::delete_object_tagging::DeleteObjectTaggingError,
> {
    Ok({
        #[allow(unused_mut)]
        let mut output = crate::operation::delete_object_tagging::builders::DeleteObjectTaggingOutputBuilder::default();
        output = output.set_version_id(
            crate::protocol_serde::shape_delete_object_tagging_output::de_version_id_header(_response_headers).map_err(|_| {
                crate::operation::delete_object_tagging::DeleteObjectTaggingError::unhandled(
                    "Failed to parse VersionId from header `x-amz-version-id",
                )
            })?,
        );
        output._set_extended_request_id(crate::s3_request_id::RequestIdExt::extended_request_id(_response_headers).map(str::to_string));
        output._set_request_id(::aws_types::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        output.build()
    })
}

pub fn ser_delete_object_tagging_headers(
    input: &crate::operation::delete_object_tagging::DeleteObjectTaggingInput,
    mut builder: ::http::request::Builder,
) -> std::result::Result<::http::request::Builder, ::aws_smithy_types::error::operation::BuildError> {
    if let ::std::option::Option::Some(inner_1) = &input.expected_bucket_owner {
        let formatted_2 = inner_1.as_str();
        if !formatted_2.is_empty() {
            let header_value = formatted_2;
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