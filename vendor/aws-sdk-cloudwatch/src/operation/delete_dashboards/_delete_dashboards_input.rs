// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDashboardsInput {
    /// <p>The dashboards to be deleted. This parameter is required.</p>
    pub dashboard_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeleteDashboardsInput {
    /// <p>The dashboards to be deleted. This parameter is required.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.dashboard_names.is_none()`.
    pub fn dashboard_names(&self) -> &[::std::string::String] {
        self.dashboard_names.as_deref().unwrap_or_default()
    }
}
impl DeleteDashboardsInput {
    /// Creates a new builder-style object to manufacture [`DeleteDashboardsInput`](crate::operation::delete_dashboards::DeleteDashboardsInput).
    pub fn builder() -> crate::operation::delete_dashboards::builders::DeleteDashboardsInputBuilder {
        crate::operation::delete_dashboards::builders::DeleteDashboardsInputBuilder::default()
    }
}

/// A builder for [`DeleteDashboardsInput`](crate::operation::delete_dashboards::DeleteDashboardsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteDashboardsInputBuilder {
    pub(crate) dashboard_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeleteDashboardsInputBuilder {
    /// Appends an item to `dashboard_names`.
    ///
    /// To override the contents of this collection use [`set_dashboard_names`](Self::set_dashboard_names).
    ///
    /// <p>The dashboards to be deleted. This parameter is required.</p>
    pub fn dashboard_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.dashboard_names.unwrap_or_default();
        v.push(input.into());
        self.dashboard_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The dashboards to be deleted. This parameter is required.</p>
    pub fn set_dashboard_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.dashboard_names = input;
        self
    }
    /// <p>The dashboards to be deleted. This parameter is required.</p>
    pub fn get_dashboard_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.dashboard_names
    }
    /// Consumes the builder and constructs a [`DeleteDashboardsInput`](crate::operation::delete_dashboards::DeleteDashboardsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_dashboards::DeleteDashboardsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_dashboards::DeleteDashboardsInput {
            dashboard_names: self.dashboard_names,
        })
    }
}