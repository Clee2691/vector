// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_redshift_destination_update(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::types::RedshiftDestinationUpdate,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.role_arn {
        object.key("RoleARN").string(var_1.as_str());
    }
    if let Some(var_2) = &input.cluster_jdbcurl {
        object.key("ClusterJDBCURL").string(var_2.as_str());
    }
    if let Some(var_3) = &input.copy_command {
        #[allow(unused_mut)]
        let mut object_4 = object.key("CopyCommand").start_object();
        crate::protocol_serde::shape_copy_command::ser_copy_command(&mut object_4, var_3)?;
        object_4.finish();
    }
    if let Some(var_5) = &input.username {
        object.key("Username").string(var_5.as_str());
    }
    if let Some(var_6) = &input.password {
        object.key("Password").string(var_6.as_str());
    }
    if let Some(var_7) = &input.retry_options {
        #[allow(unused_mut)]
        let mut object_8 = object.key("RetryOptions").start_object();
        crate::protocol_serde::shape_redshift_retry_options::ser_redshift_retry_options(&mut object_8, var_7)?;
        object_8.finish();
    }
    if let Some(var_9) = &input.s3_update {
        #[allow(unused_mut)]
        let mut object_10 = object.key("S3Update").start_object();
        crate::protocol_serde::shape_s3_destination_update::ser_s3_destination_update(&mut object_10, var_9)?;
        object_10.finish();
    }
    if let Some(var_11) = &input.processing_configuration {
        #[allow(unused_mut)]
        let mut object_12 = object.key("ProcessingConfiguration").start_object();
        crate::protocol_serde::shape_processing_configuration::ser_processing_configuration(&mut object_12, var_11)?;
        object_12.finish();
    }
    if let Some(var_13) = &input.s3_backup_mode {
        object.key("S3BackupMode").string(var_13.as_str());
    }
    if let Some(var_14) = &input.s3_backup_update {
        #[allow(unused_mut)]
        let mut object_15 = object.key("S3BackupUpdate").start_object();
        crate::protocol_serde::shape_s3_destination_update::ser_s3_destination_update(&mut object_15, var_14)?;
        object_15.finish();
    }
    if let Some(var_16) = &input.cloud_watch_logging_options {
        #[allow(unused_mut)]
        let mut object_17 = object.key("CloudWatchLoggingOptions").start_object();
        crate::protocol_serde::shape_cloud_watch_logging_options::ser_cloud_watch_logging_options(&mut object_17, var_16)?;
        object_17.finish();
    }
    Ok(())
}