// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(unused_mut)]
pub fn ser_single_metric_anomaly_detector(
    mut writer: ::aws_smithy_query::QueryValueWriter,
    input: &crate::types::SingleMetricAnomalyDetector,
) -> Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    #[allow(unused_mut)]
    let mut scope_1 = writer.prefix("Namespace");
    if let Some(var_2) = &input.namespace {
        scope_1.string(var_2);
    }
    #[allow(unused_mut)]
    let mut scope_3 = writer.prefix("MetricName");
    if let Some(var_4) = &input.metric_name {
        scope_3.string(var_4);
    }
    #[allow(unused_mut)]
    let mut scope_5 = writer.prefix("Dimensions");
    if let Some(var_6) = &input.dimensions {
        let mut list_8 = scope_5.start_list(false, None);
        for item_7 in var_6 {
            #[allow(unused_mut)]
            let mut entry_9 = list_8.entry();
            crate::protocol_serde::shape_dimension::ser_dimension(entry_9, item_7)?;
        }
        list_8.finish();
    }
    #[allow(unused_mut)]
    let mut scope_10 = writer.prefix("Stat");
    if let Some(var_11) = &input.stat {
        scope_10.string(var_11);
    }
    Ok(())
}

#[allow(clippy::needless_question_mark)]
pub fn de_single_metric_anomaly_detector(
    decoder: &mut ::aws_smithy_xml::decode::ScopedDecoder,
) -> Result<crate::types::SingleMetricAnomalyDetector, ::aws_smithy_xml::decode::XmlDecodeError> {
    #[allow(unused_mut)]
    let mut builder = crate::types::SingleMetricAnomalyDetector::builder();
    while let Some(mut tag) = decoder.next_tag() {
        match tag.start_el() {
            s if s.matches("Namespace") /* Namespace com.amazonaws.cloudwatch#SingleMetricAnomalyDetector$Namespace */ =>  {
                let var_12 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_namespace(var_12);
            }
            ,
            s if s.matches("MetricName") /* MetricName com.amazonaws.cloudwatch#SingleMetricAnomalyDetector$MetricName */ =>  {
                let var_13 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_metric_name(var_13);
            }
            ,
            s if s.matches("Dimensions") /* Dimensions com.amazonaws.cloudwatch#SingleMetricAnomalyDetector$Dimensions */ =>  {
                let var_14 =
                    Some(
                        crate::protocol_serde::shape_dimensions::de_dimensions(&mut tag)
                        ?
                    )
                ;
                builder = builder.set_dimensions(var_14);
            }
            ,
            s if s.matches("Stat") /* Stat com.amazonaws.cloudwatch#SingleMetricAnomalyDetector$Stat */ =>  {
                let var_15 =
                    Some(
                        Result::<::std::string::String, ::aws_smithy_xml::decode::XmlDecodeError>::Ok(
                            ::aws_smithy_xml::decode::try_data(&mut tag)?.as_ref()
                            .into()
                        )
                        ?
                    )
                ;
                builder = builder.set_stat(var_15);
            }
            ,
            _ => {}
        }
    }
    Ok(builder.build())
}