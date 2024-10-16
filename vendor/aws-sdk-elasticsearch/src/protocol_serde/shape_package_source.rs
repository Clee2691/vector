// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_package_source(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::types::PackageSource,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.s3_bucket_name {
        object.key("S3BucketName").string(var_1.as_str());
    }
    if let Some(var_2) = &input.s3_key {
        object.key("S3Key").string(var_2.as_str());
    }
    Ok(())
}