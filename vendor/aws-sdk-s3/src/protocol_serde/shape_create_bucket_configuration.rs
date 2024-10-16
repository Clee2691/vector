// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_create_bucket_configuration(
    input: &crate::types::CreateBucketConfiguration,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    if let Some(var_1) = &input.location_constraint {
        let mut inner_writer = scope.start_el("LocationConstraint").finish();
        inner_writer.data(var_1.as_str());
    }
    if let Some(var_2) = &input.location {
        let inner_writer = scope.start_el("Location");
        crate::protocol_serde::shape_location_info::ser_location_info(var_2, inner_writer)?
    }
    if let Some(var_3) = &input.bucket {
        let inner_writer = scope.start_el("Bucket");
        crate::protocol_serde::shape_bucket_info::ser_bucket_info(var_3, inner_writer)?
    }
    scope.finish();
    Ok(())
}