// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInsightRulesInput {
    /// <p>An array of the rule names to delete. If you need to find out the names of your rules, use <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeInsightRules.html">DescribeInsightRules</a>.</p>
    pub rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeleteInsightRulesInput {
    /// <p>An array of the rule names to delete. If you need to find out the names of your rules, use <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeInsightRules.html">DescribeInsightRules</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rule_names.is_none()`.
    pub fn rule_names(&self) -> &[::std::string::String] {
        self.rule_names.as_deref().unwrap_or_default()
    }
}
impl DeleteInsightRulesInput {
    /// Creates a new builder-style object to manufacture [`DeleteInsightRulesInput`](crate::operation::delete_insight_rules::DeleteInsightRulesInput).
    pub fn builder() -> crate::operation::delete_insight_rules::builders::DeleteInsightRulesInputBuilder {
        crate::operation::delete_insight_rules::builders::DeleteInsightRulesInputBuilder::default()
    }
}

/// A builder for [`DeleteInsightRulesInput`](crate::operation::delete_insight_rules::DeleteInsightRulesInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct DeleteInsightRulesInputBuilder {
    pub(crate) rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeleteInsightRulesInputBuilder {
    /// Appends an item to `rule_names`.
    ///
    /// To override the contents of this collection use [`set_rule_names`](Self::set_rule_names).
    ///
    /// <p>An array of the rule names to delete. If you need to find out the names of your rules, use <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeInsightRules.html">DescribeInsightRules</a>.</p>
    pub fn rule_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.rule_names.unwrap_or_default();
        v.push(input.into());
        self.rule_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of the rule names to delete. If you need to find out the names of your rules, use <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeInsightRules.html">DescribeInsightRules</a>.</p>
    pub fn set_rule_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.rule_names = input;
        self
    }
    /// <p>An array of the rule names to delete. If you need to find out the names of your rules, use <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeInsightRules.html">DescribeInsightRules</a>.</p>
    pub fn get_rule_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.rule_names
    }
    /// Consumes the builder and constructs a [`DeleteInsightRulesInput`](crate::operation::delete_insight_rules::DeleteInsightRulesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_insight_rules::DeleteInsightRulesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_insight_rules::DeleteInsightRulesInput { rule_names: self.rule_names })
    }
}