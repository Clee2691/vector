// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_get_dashboard_input_input_input(
    input: &crate::operation::get_dashboard::GetDashboardInput,
) -> Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    #[allow(unused_mut)]
    let mut writer = ::aws_smithy_query::QueryWriter::new(&mut out, "GetDashboard", "2010-08-01");
    #[allow(unused_mut)]
    let mut scope_1 = writer.prefix("DashboardName");
    if let Some(var_2) = &input.dashboard_name {
        scope_1.string(var_2);
    }
    writer.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}