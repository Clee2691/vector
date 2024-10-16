// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutManagedInsightRulesOutput {
    /// <p> An array that lists the rules that could not be enabled. </p>
    pub failures: ::std::option::Option<::std::vec::Vec<crate::types::PartialFailure>>,
    _request_id: Option<String>,
}
impl PutManagedInsightRulesOutput {
    /// <p> An array that lists the rules that could not be enabled. </p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failures.is_none()`.
    pub fn failures(&self) -> &[crate::types::PartialFailure] {
        self.failures.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for PutManagedInsightRulesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutManagedInsightRulesOutput {
    /// Creates a new builder-style object to manufacture [`PutManagedInsightRulesOutput`](crate::operation::put_managed_insight_rules::PutManagedInsightRulesOutput).
    pub fn builder() -> crate::operation::put_managed_insight_rules::builders::PutManagedInsightRulesOutputBuilder {
        crate::operation::put_managed_insight_rules::builders::PutManagedInsightRulesOutputBuilder::default()
    }
}

/// A builder for [`PutManagedInsightRulesOutput`](crate::operation::put_managed_insight_rules::PutManagedInsightRulesOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutManagedInsightRulesOutputBuilder {
    pub(crate) failures: ::std::option::Option<::std::vec::Vec<crate::types::PartialFailure>>,
    _request_id: Option<String>,
}
impl PutManagedInsightRulesOutputBuilder {
    /// Appends an item to `failures`.
    ///
    /// To override the contents of this collection use [`set_failures`](Self::set_failures).
    ///
    /// <p> An array that lists the rules that could not be enabled. </p>
    pub fn failures(mut self, input: crate::types::PartialFailure) -> Self {
        let mut v = self.failures.unwrap_or_default();
        v.push(input);
        self.failures = ::std::option::Option::Some(v);
        self
    }
    /// <p> An array that lists the rules that could not be enabled. </p>
    pub fn set_failures(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PartialFailure>>) -> Self {
        self.failures = input;
        self
    }
    /// <p> An array that lists the rules that could not be enabled. </p>
    pub fn get_failures(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PartialFailure>> {
        &self.failures
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutManagedInsightRulesOutput`](crate::operation::put_managed_insight_rules::PutManagedInsightRulesOutput).
    pub fn build(self) -> crate::operation::put_managed_insight_rules::PutManagedInsightRulesOutput {
        crate::operation::put_managed_insight_rules::PutManagedInsightRulesOutput {
            failures: self.failures,
            _request_id: self._request_id,
        }
    }
}