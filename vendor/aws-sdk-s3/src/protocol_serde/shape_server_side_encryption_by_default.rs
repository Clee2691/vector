// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_server_side_encryption_by_default(
    input: &crate::types::ServerSideEncryptionByDefault,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    {
        let mut inner_writer = scope.start_el("SSEAlgorithm").finish();
        inner_writer.data(input.sse_algorithm.as_str());
    }
    if let Some(var_1) = &input.kms_master_key_id {
        let mut inner_writer = scope.start_el("KMSMasterKeyID").finish();
        inner_writer.data(var_1.as_str());
    }
    scope.finish();
    Ok(())
}

#[allow(clippy::needless_question_mark)]
pub fn de_server_side_encryption_by_default(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::ServerSideEncryptionByDefault, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::ServerSideEncryptionByDefault::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("SSEAlgorithm") /* SSEAlgorithm com.amazonaws.s3#ServerSideEncryptionByDefault$SSEAlgorithm */ =>  {
                let var_2 =
                    Some(
                        Result::<crate::types::ServerSideEncryption, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            crate::types::ServerSideEncryption::from(
                                ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            )
                        )
                        ?
                    )
                ;
                builder = builder.set_sse_algorithm(var_2);
            }
            ,
            s if s.matches("KMSMasterKeyID") /* KMSMasterKeyID com.amazonaws.s3#ServerSideEncryptionByDefault$KMSMasterKeyID */ =>  {
                let var_3 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_kms_master_key_id(var_3);
            }
            ,
            _ => {}
        }
    }
    Ok(crate::serde_util::server_side_encryption_by_default_correct_errors(builder)
        .build()
        .map_err(|_| ::aws_smithy_xml::decode::XmlDecodeError::custom("missing field"))?)
}