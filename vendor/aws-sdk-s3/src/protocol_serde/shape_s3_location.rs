// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_s3_location(
    input: &crate::types::S3Location,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    {
        let mut inner_writer = scope.start_el("BucketName").finish();
        inner_writer.data(input.bucket_name.as_str());
    }
    {
        let mut inner_writer = scope.start_el("Prefix").finish();
        inner_writer.data(input.prefix.as_str());
    }
    if let Some(var_1) = &input.encryption {
        let inner_writer = scope.start_el("Encryption");
        crate::protocol_serde::shape_encryption::ser_encryption(var_1, inner_writer)?
    }
    if let Some(var_2) = &input.canned_acl {
        let mut inner_writer = scope.start_el("CannedACL").finish();
        inner_writer.data(var_2.as_str());
    }
    if let Some(var_3) = &input.access_control_list {
        let mut inner_writer = scope.start_el("AccessControlList").finish();
        for list_item_4 in var_3 {
            {
                let inner_writer = inner_writer.start_el("Grant");
                crate::protocol_serde::shape_grant::ser_grant(list_item_4, inner_writer)?
            }
        }
    }
    if let Some(var_5) = &input.tagging {
        let inner_writer = scope.start_el("Tagging");
        crate::protocol_serde::shape_tagging::ser_tagging(var_5, inner_writer)?
    }
    if let Some(var_6) = &input.user_metadata {
        let mut inner_writer = scope.start_el("UserMetadata").finish();
        for list_item_7 in var_6 {
            {
                let inner_writer = inner_writer.start_el("MetadataEntry");
                crate::protocol_serde::shape_metadata_entry::ser_metadata_entry(list_item_7, inner_writer)?
            }
        }
    }
    if let Some(var_8) = &input.storage_class {
        let mut inner_writer = scope.start_el("StorageClass").finish();
        inner_writer.data(var_8.as_str());
    }
    scope.finish();
    Ok(())
}