// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_replication_configuration(
    input: &crate::types::ReplicationConfiguration,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    {
        let mut inner_writer = scope.start_el("Role").finish();
        inner_writer.data(input.role.as_str());
    }
    {
        for list_item_1 in &input.rules {
            {
                let inner_writer = scope.start_el("Rule");
                crate::protocol_serde::shape_replication_rule::ser_replication_rule(list_item_1, inner_writer)?
            }
        }
    }
    scope.finish();
    Ok(())
}

#[allow(clippy::needless_question_mark)]
pub fn de_replication_configuration(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::ReplicationConfiguration, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::ReplicationConfiguration::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("Role") /* Role com.amazonaws.s3#ReplicationConfiguration$Role */ =>  {
                let var_2 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_role(var_2);
            }
            ,
            s if s.matches("Rule") /* Rules com.amazonaws.s3#ReplicationConfiguration$Rules */ =>  {
                let var_3 =
                    Some(
                        Result::<::std::vec::Vec::<crate::types::ReplicationRule>, ::aws_smithy_xml::decode::XmlDecodeError>::Ok({
                            let mut list_4 = builder.rules.take().unwrap_or_default();
                            list_4.push(
                                crate::protocol_serde::shape_replication_rule::de_replication_rule(&mut tag)
                                ?
                            );
                            list_4
                        })
                        ?
                    )
                ;
                builder = builder.set_rules(var_3);
            }
            ,
            _ => {}
        }
    }
    Ok(crate::serde_util::replication_configuration_correct_errors(builder)
        .build()
        .map_err(|_| ::aws_smithy_xml::decode::XmlDecodeError::custom("missing field"))?)
}