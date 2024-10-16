// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub(crate) fn de_access_point_alias_header(
    header_map: &::aws_smithy_runtime_api::http::Headers,
) -> ::std::result::Result<::std::option::Option<bool>, ::aws_smithy_http::header::ParseError> {
    let headers = header_map.get_all("x-amz-access-point-alias");
    let var_1 = ::aws_smithy_http::header::read_many_primitive::<bool>(headers)?;
    if var_1.len() > 1 {
        Err(::aws_smithy_http::header::ParseError::new(format!(
            "expected one item but found {}",
            var_1.len()
        )))
    } else {
        let mut var_1 = var_1;
        Ok(var_1.pop())
    }
}

pub(crate) fn de_bucket_location_name_header(
    header_map: &::aws_smithy_runtime_api::http::Headers,
) -> ::std::result::Result<::std::option::Option<::std::string::String>, ::aws_smithy_http::header::ParseError> {
    let headers = header_map.get_all("x-amz-bucket-location-name");
    ::aws_smithy_http::header::one_or_none(headers)
}

pub(crate) fn de_bucket_location_type_header(
    header_map: &::aws_smithy_runtime_api::http::Headers,
) -> ::std::result::Result<::std::option::Option<crate::types::LocationType>, ::aws_smithy_http::header::ParseError> {
    let headers = header_map.get_all("x-amz-bucket-location-type");
    ::aws_smithy_http::header::one_or_none(headers)
}

pub(crate) fn de_bucket_region_header(
    header_map: &::aws_smithy_runtime_api::http::Headers,
) -> ::std::result::Result<::std::option::Option<::std::string::String>, ::aws_smithy_http::header::ParseError> {
    let headers = header_map.get_all("x-amz-bucket-region");
    ::aws_smithy_http::header::one_or_none(headers)
}