// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::needless_question_mark)]
pub fn de_intelligent_tiering_filter(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::IntelligentTieringFilter, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::IntelligentTieringFilter::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("Prefix") /* Prefix com.amazonaws.s3#IntelligentTieringFilter$Prefix */ =>  {
                let var_1 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_prefix(var_1);
            }
            ,
            s if s.matches("Tag") /* Tag com.amazonaws.s3#IntelligentTieringFilter$Tag */ =>  {
                let var_2 =
                    Some(
                        crate::protocol_serde::shape_tag::de_tag(&mut tag)
                        ?
                    )
                ;
                builder = builder.set_tag(var_2);
            }
            ,
            s if s.matches("And") /* And com.amazonaws.s3#IntelligentTieringFilter$And */ =>  {
                let var_3 =
                    Some(
                        crate::protocol_serde::shape_intelligent_tiering_and_operator::de_intelligent_tiering_and_operator(&mut tag)
                        ?
                    )
                ;
                builder = builder.set_and(var_3);
            }
            ,
            _ => {}
        }
    }
    Ok(builder.build())
}

pub fn ser_intelligent_tiering_filter(
    input: &crate::types::IntelligentTieringFilter,
    writer: ::aws_smithy_xml::encode::ElWriter,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope = writer.finish();
    if let Some(var_4) = &input.prefix {
        let mut inner_writer = scope.start_el("Prefix").finish();
        inner_writer.data(var_4.as_str());
    }
    if let Some(var_5) = &input.tag {
        let inner_writer = scope.start_el("Tag");
        crate::protocol_serde::shape_tag::ser_tag(var_5, inner_writer)?
    }
    if let Some(var_6) = &input.and {
        let inner_writer = scope.start_el("And");
        crate::protocol_serde::shape_intelligent_tiering_and_operator::ser_intelligent_tiering_and_operator(var_6, inner_writer)?
    }
    scope.finish();
    Ok(())
}