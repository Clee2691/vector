// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAccountPolicyInput {
    /// <p>A name for the policy. This must be unique within the account.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>Specify the data protection policy, in JSON.</p>
    /// <p>This policy must include two JSON blocks:</p>
    /// <ul>
    /// <li> <p>The first block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Audit</code> action. The <code>DataIdentifer</code> array lists the types of sensitive data that you want to mask. For more information about the available options, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-types.html">Types of data that you can mask</a>.</p> <p>The <code>Operation</code> property with an <code>Audit</code> action is required to find the sensitive data terms. This <code>Audit</code> action must contain a <code>FindingsDestination</code> object. You can optionally use that <code>FindingsDestination</code> object to list one or more destinations to send audit findings to. If you specify destinations such as log groups, Kinesis Data Firehose streams, and S3 buckets, they must already exist.</p> </li>
    /// <li> <p>The second block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Deidentify</code> action. The <code>DataIdentifer</code> array must exactly match the <code>DataIdentifer</code> array in the first block of the policy.</p> <p>The <code>Operation</code> property with the <code>Deidentify</code> action is what actually masks the data, and it must contain the <code> "MaskConfig": {}</code> object. The <code> "MaskConfig": {}</code> object must be empty.</p> </li>
    /// </ul>
    /// <p>For an example data protection policy, see the <b>Examples</b> section on this page.</p> <important>
    /// <p>The contents of the two <code>DataIdentifer</code> arrays must match exactly.</p>
    /// </important>
    /// <p>In addition to the two JSON blocks, the <code>policyDocument</code> can also include <code>Name</code>, <code>Description</code>, and <code>Version</code> fields. The <code>Name</code> is different than the operation's <code>policyName</code> parameter, and is used as a dimension when CloudWatch Logs reports audit findings metrics to CloudWatch.</p>
    /// <p>The JSON specified in <code>policyDocument</code> can be up to 30,720 characters.</p>
    pub policy_document: ::std::option::Option<::std::string::String>,
    /// <p>Currently the only valid value for this parameter is <code>DATA_PROTECTION_POLICY</code>.</p>
    pub policy_type: ::std::option::Option<crate::types::PolicyType>,
    /// <p>Currently the only valid value for this parameter is <code>ALL</code>, which specifies that the data protection policy applies to all log groups in the account. If you omit this parameter, the default of <code>ALL</code> is used.</p>
    pub scope: ::std::option::Option<crate::types::Scope>,
}
impl PutAccountPolicyInput {
    /// <p>A name for the policy. This must be unique within the account.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>Specify the data protection policy, in JSON.</p>
    /// <p>This policy must include two JSON blocks:</p>
    /// <ul>
    /// <li> <p>The first block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Audit</code> action. The <code>DataIdentifer</code> array lists the types of sensitive data that you want to mask. For more information about the available options, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-types.html">Types of data that you can mask</a>.</p> <p>The <code>Operation</code> property with an <code>Audit</code> action is required to find the sensitive data terms. This <code>Audit</code> action must contain a <code>FindingsDestination</code> object. You can optionally use that <code>FindingsDestination</code> object to list one or more destinations to send audit findings to. If you specify destinations such as log groups, Kinesis Data Firehose streams, and S3 buckets, they must already exist.</p> </li>
    /// <li> <p>The second block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Deidentify</code> action. The <code>DataIdentifer</code> array must exactly match the <code>DataIdentifer</code> array in the first block of the policy.</p> <p>The <code>Operation</code> property with the <code>Deidentify</code> action is what actually masks the data, and it must contain the <code> "MaskConfig": {}</code> object. The <code> "MaskConfig": {}</code> object must be empty.</p> </li>
    /// </ul>
    /// <p>For an example data protection policy, see the <b>Examples</b> section on this page.</p> <important>
    /// <p>The contents of the two <code>DataIdentifer</code> arrays must match exactly.</p>
    /// </important>
    /// <p>In addition to the two JSON blocks, the <code>policyDocument</code> can also include <code>Name</code>, <code>Description</code>, and <code>Version</code> fields. The <code>Name</code> is different than the operation's <code>policyName</code> parameter, and is used as a dimension when CloudWatch Logs reports audit findings metrics to CloudWatch.</p>
    /// <p>The JSON specified in <code>policyDocument</code> can be up to 30,720 characters.</p>
    pub fn policy_document(&self) -> ::std::option::Option<&str> {
        self.policy_document.as_deref()
    }
    /// <p>Currently the only valid value for this parameter is <code>DATA_PROTECTION_POLICY</code>.</p>
    pub fn policy_type(&self) -> ::std::option::Option<&crate::types::PolicyType> {
        self.policy_type.as_ref()
    }
    /// <p>Currently the only valid value for this parameter is <code>ALL</code>, which specifies that the data protection policy applies to all log groups in the account. If you omit this parameter, the default of <code>ALL</code> is used.</p>
    pub fn scope(&self) -> ::std::option::Option<&crate::types::Scope> {
        self.scope.as_ref()
    }
}
impl PutAccountPolicyInput {
    /// Creates a new builder-style object to manufacture [`PutAccountPolicyInput`](crate::operation::put_account_policy::PutAccountPolicyInput).
    pub fn builder() -> crate::operation::put_account_policy::builders::PutAccountPolicyInputBuilder {
        crate::operation::put_account_policy::builders::PutAccountPolicyInputBuilder::default()
    }
}

/// A builder for [`PutAccountPolicyInput`](crate::operation::put_account_policy::PutAccountPolicyInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutAccountPolicyInputBuilder {
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) policy_document: ::std::option::Option<::std::string::String>,
    pub(crate) policy_type: ::std::option::Option<crate::types::PolicyType>,
    pub(crate) scope: ::std::option::Option<crate::types::Scope>,
}
impl PutAccountPolicyInputBuilder {
    /// <p>A name for the policy. This must be unique within the account.</p>
    /// This field is required.
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the policy. This must be unique within the account.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>A name for the policy. This must be unique within the account.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// <p>Specify the data protection policy, in JSON.</p>
    /// <p>This policy must include two JSON blocks:</p>
    /// <ul>
    /// <li> <p>The first block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Audit</code> action. The <code>DataIdentifer</code> array lists the types of sensitive data that you want to mask. For more information about the available options, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-types.html">Types of data that you can mask</a>.</p> <p>The <code>Operation</code> property with an <code>Audit</code> action is required to find the sensitive data terms. This <code>Audit</code> action must contain a <code>FindingsDestination</code> object. You can optionally use that <code>FindingsDestination</code> object to list one or more destinations to send audit findings to. If you specify destinations such as log groups, Kinesis Data Firehose streams, and S3 buckets, they must already exist.</p> </li>
    /// <li> <p>The second block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Deidentify</code> action. The <code>DataIdentifer</code> array must exactly match the <code>DataIdentifer</code> array in the first block of the policy.</p> <p>The <code>Operation</code> property with the <code>Deidentify</code> action is what actually masks the data, and it must contain the <code> "MaskConfig": {}</code> object. The <code> "MaskConfig": {}</code> object must be empty.</p> </li>
    /// </ul>
    /// <p>For an example data protection policy, see the <b>Examples</b> section on this page.</p> <important>
    /// <p>The contents of the two <code>DataIdentifer</code> arrays must match exactly.</p>
    /// </important>
    /// <p>In addition to the two JSON blocks, the <code>policyDocument</code> can also include <code>Name</code>, <code>Description</code>, and <code>Version</code> fields. The <code>Name</code> is different than the operation's <code>policyName</code> parameter, and is used as a dimension when CloudWatch Logs reports audit findings metrics to CloudWatch.</p>
    /// <p>The JSON specified in <code>policyDocument</code> can be up to 30,720 characters.</p>
    /// This field is required.
    pub fn policy_document(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_document = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the data protection policy, in JSON.</p>
    /// <p>This policy must include two JSON blocks:</p>
    /// <ul>
    /// <li> <p>The first block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Audit</code> action. The <code>DataIdentifer</code> array lists the types of sensitive data that you want to mask. For more information about the available options, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-types.html">Types of data that you can mask</a>.</p> <p>The <code>Operation</code> property with an <code>Audit</code> action is required to find the sensitive data terms. This <code>Audit</code> action must contain a <code>FindingsDestination</code> object. You can optionally use that <code>FindingsDestination</code> object to list one or more destinations to send audit findings to. If you specify destinations such as log groups, Kinesis Data Firehose streams, and S3 buckets, they must already exist.</p> </li>
    /// <li> <p>The second block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Deidentify</code> action. The <code>DataIdentifer</code> array must exactly match the <code>DataIdentifer</code> array in the first block of the policy.</p> <p>The <code>Operation</code> property with the <code>Deidentify</code> action is what actually masks the data, and it must contain the <code> "MaskConfig": {}</code> object. The <code> "MaskConfig": {}</code> object must be empty.</p> </li>
    /// </ul>
    /// <p>For an example data protection policy, see the <b>Examples</b> section on this page.</p> <important>
    /// <p>The contents of the two <code>DataIdentifer</code> arrays must match exactly.</p>
    /// </important>
    /// <p>In addition to the two JSON blocks, the <code>policyDocument</code> can also include <code>Name</code>, <code>Description</code>, and <code>Version</code> fields. The <code>Name</code> is different than the operation's <code>policyName</code> parameter, and is used as a dimension when CloudWatch Logs reports audit findings metrics to CloudWatch.</p>
    /// <p>The JSON specified in <code>policyDocument</code> can be up to 30,720 characters.</p>
    pub fn set_policy_document(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_document = input;
        self
    }
    /// <p>Specify the data protection policy, in JSON.</p>
    /// <p>This policy must include two JSON blocks:</p>
    /// <ul>
    /// <li> <p>The first block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Audit</code> action. The <code>DataIdentifer</code> array lists the types of sensitive data that you want to mask. For more information about the available options, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-types.html">Types of data that you can mask</a>.</p> <p>The <code>Operation</code> property with an <code>Audit</code> action is required to find the sensitive data terms. This <code>Audit</code> action must contain a <code>FindingsDestination</code> object. You can optionally use that <code>FindingsDestination</code> object to list one or more destinations to send audit findings to. If you specify destinations such as log groups, Kinesis Data Firehose streams, and S3 buckets, they must already exist.</p> </li>
    /// <li> <p>The second block must include both a <code>DataIdentifer</code> array and an <code>Operation</code> property with an <code>Deidentify</code> action. The <code>DataIdentifer</code> array must exactly match the <code>DataIdentifer</code> array in the first block of the policy.</p> <p>The <code>Operation</code> property with the <code>Deidentify</code> action is what actually masks the data, and it must contain the <code> "MaskConfig": {}</code> object. The <code> "MaskConfig": {}</code> object must be empty.</p> </li>
    /// </ul>
    /// <p>For an example data protection policy, see the <b>Examples</b> section on this page.</p> <important>
    /// <p>The contents of the two <code>DataIdentifer</code> arrays must match exactly.</p>
    /// </important>
    /// <p>In addition to the two JSON blocks, the <code>policyDocument</code> can also include <code>Name</code>, <code>Description</code>, and <code>Version</code> fields. The <code>Name</code> is different than the operation's <code>policyName</code> parameter, and is used as a dimension when CloudWatch Logs reports audit findings metrics to CloudWatch.</p>
    /// <p>The JSON specified in <code>policyDocument</code> can be up to 30,720 characters.</p>
    pub fn get_policy_document(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_document
    }
    /// <p>Currently the only valid value for this parameter is <code>DATA_PROTECTION_POLICY</code>.</p>
    /// This field is required.
    pub fn policy_type(mut self, input: crate::types::PolicyType) -> Self {
        self.policy_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Currently the only valid value for this parameter is <code>DATA_PROTECTION_POLICY</code>.</p>
    pub fn set_policy_type(mut self, input: ::std::option::Option<crate::types::PolicyType>) -> Self {
        self.policy_type = input;
        self
    }
    /// <p>Currently the only valid value for this parameter is <code>DATA_PROTECTION_POLICY</code>.</p>
    pub fn get_policy_type(&self) -> &::std::option::Option<crate::types::PolicyType> {
        &self.policy_type
    }
    /// <p>Currently the only valid value for this parameter is <code>ALL</code>, which specifies that the data protection policy applies to all log groups in the account. If you omit this parameter, the default of <code>ALL</code> is used.</p>
    pub fn scope(mut self, input: crate::types::Scope) -> Self {
        self.scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Currently the only valid value for this parameter is <code>ALL</code>, which specifies that the data protection policy applies to all log groups in the account. If you omit this parameter, the default of <code>ALL</code> is used.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<crate::types::Scope>) -> Self {
        self.scope = input;
        self
    }
    /// <p>Currently the only valid value for this parameter is <code>ALL</code>, which specifies that the data protection policy applies to all log groups in the account. If you omit this parameter, the default of <code>ALL</code> is used.</p>
    pub fn get_scope(&self) -> &::std::option::Option<crate::types::Scope> {
        &self.scope
    }
    /// Consumes the builder and constructs a [`PutAccountPolicyInput`](crate::operation::put_account_policy::PutAccountPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_account_policy::PutAccountPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_account_policy::PutAccountPolicyInput {
            policy_name: self.policy_name,
            policy_document: self.policy_document,
            policy_type: self.policy_type,
            scope: self.scope,
        })
    }
}