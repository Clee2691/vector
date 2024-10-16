// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ListDashboards`](crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder) operation.
    /// This operation supports pagination; See [`into_paginator()`](crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder::into_paginator).
    ///
    /// - The fluent builder is configurable:
    ///   - [`dashboard_name_prefix(impl Into<String>)`](crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder::dashboard_name_prefix) / [`set_dashboard_name_prefix(Option<String>)`](crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder::set_dashboard_name_prefix):<br>required: **false**<br><p>If you specify this parameter, only the dashboards with names starting with the specified string are listed. The maximum length is 255, and valid characters are A-Z, a-z, 0-9, ".", "-", and "_". </p><br>
    ///   - [`next_token(impl Into<String>)`](crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder::next_token) / [`set_next_token(Option<String>)`](crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder::set_next_token):<br>required: **false**<br><p>The token returned by a previous call to indicate that there is more data available.</p><br>
    /// - On success, responds with [`ListDashboardsOutput`](crate::operation::list_dashboards::ListDashboardsOutput) with field(s):
    ///   - [`dashboard_entries(Option<Vec::<DashboardEntry>>)`](crate::operation::list_dashboards::ListDashboardsOutput::dashboard_entries): <p>The list of matching dashboards.</p>
    ///   - [`next_token(Option<String>)`](crate::operation::list_dashboards::ListDashboardsOutput::next_token): <p>The token that marks the start of the next batch of returned results.</p>
    /// - On failure, responds with [`SdkError<ListDashboardsError>`](crate::operation::list_dashboards::ListDashboardsError)
    pub fn list_dashboards(&self) -> crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder {
        crate::operation::list_dashboards::builders::ListDashboardsFluentBuilder::new(self.handle.clone())
    }
}