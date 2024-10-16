// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::needless_question_mark)]
pub fn de_analytics_s3_bucket_destination(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::AnalyticsS3BucketDestination, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::AnalyticsS3BucketDestination::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("Format") /* Format com.amazonaws.s3#AnalyticsS3BucketDestination$Format */ =>  {
                let var_1 =
                    Some(
                        Result::<crate::types::AnalyticsS3ExportFileFormat, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            crate::types::AnalyticsS3ExportFileFormat::from(
                                ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            )
                        )
                        ?
                    )
                ;
                builder = builder.set_format(var_1);
            }
            ,
            s if s.matches("BucketAccountId") /* BucketAccountId com.amazonaws.s3#AnalyticsS3BucketDestination$BucketAccountId */ =>  {
                let var_2 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_bucket_account_id(var_2);
            }
            ,
            s if s.matches("Bucket") /* Bucket com.amazonaws.s3#AnalyticsS3BucketDestination$Bucket */ =>  {
                let var_3 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_bucket(var_3);
            }
            ,
            s if s.matches("Prefix") /* Prefix com.amazonaws.s3#AnalyticsS3BucketDestination$Prefix */ =>  {
                let var_4 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_prefix(var_4);
            }
            ,
            _ => {}
        }
    }
    Ok(crate::serde_util::analytics_s3_bucket_destination_correct_errors(builder)
        .build()
        .map_err(|_| ::aws_smithy_xml::decode::XmlDecodeError::custom("missing field"))?)
}

pub fn ser_analytics_s3_bucket_destination(
    input: &crate::types::AnalyticsS3BucketDestination,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    {
        let mut inner_writer = scope.start_el("Format").finish();
        inner_writer.data(input.format.as_str());
    }
    if let Some(var_5) = &input.bucket_account_id {
        let mut inner_writer = scope.start_el("BucketAccountId").finish();
        inner_writer.data(var_5.as_str());
    }
    {
        let mut inner_writer = scope.start_el("Bucket").finish();
        inner_writer.data(input.bucket.as_str());
    }
    if let Some(var_6) = &input.prefix {
        let mut inner_writer = scope.start_el("Prefix").finish();
        inner_writer.data(var_6.as_str());
    }
    scope.finish();
    Ok(())
}