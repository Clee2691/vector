// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_bucket_info(
    input: &crate::types::BucketInfo,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    if let Some(var_1) = &input.data_redundancy {
        let mut inner_writer = scope.start_el("DataRedundancy").finish();
        inner_writer.data(var_1.as_str());
    }
    if let Some(var_2) = &input.r#type {
        let mut inner_writer = scope.start_el("Type").finish();
        inner_writer.data(var_2.as_str());
    }
    scope.finish();
    Ok(())
}