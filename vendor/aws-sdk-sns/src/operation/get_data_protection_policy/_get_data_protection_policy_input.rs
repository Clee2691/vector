// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataProtectionPolicyInput {
    /// <p>The ARN of the topic whose <code>DataProtectionPolicy</code> you want to get.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the Amazon Web Services General Reference.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
}
impl GetDataProtectionPolicyInput {
    /// <p>The ARN of the topic whose <code>DataProtectionPolicy</code> you want to get.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the Amazon Web Services General Reference.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
}
impl GetDataProtectionPolicyInput {
    /// Creates a new builder-style object to manufacture [`GetDataProtectionPolicyInput`](crate::operation::get_data_protection_policy::GetDataProtectionPolicyInput).
    pub fn builder() -> crate::operation::get_data_protection_policy::builders::GetDataProtectionPolicyInputBuilder {
        crate::operation::get_data_protection_policy::builders::GetDataProtectionPolicyInputBuilder::default()
    }
}

/// A builder for [`GetDataProtectionPolicyInput`](crate::operation::get_data_protection_policy::GetDataProtectionPolicyInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetDataProtectionPolicyInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
}
impl GetDataProtectionPolicyInputBuilder {
    /// <p>The ARN of the topic whose <code>DataProtectionPolicy</code> you want to get.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the Amazon Web Services General Reference.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the topic whose <code>DataProtectionPolicy</code> you want to get.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the Amazon Web Services General Reference.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the topic whose <code>DataProtectionPolicy</code> you want to get.</p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the Amazon Web Services General Reference.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Consumes the builder and constructs a [`GetDataProtectionPolicyInput`](crate::operation::get_data_protection_policy::GetDataProtectionPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_data_protection_policy::GetDataProtectionPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_data_protection_policy::GetDataProtectionPolicyInput {
            resource_arn: self.resource_arn,
        })
    }
}