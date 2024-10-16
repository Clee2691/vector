// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutDeliverySourceInput {
    /// <p>A name for this delivery source. This name must be unique for all delivery sources in your account.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the Amazon Web Services resource that is generating and sending logs. For example, <code>arn:aws:workmail:us-east-1:123456789012:organization/m-1234EXAMPLEabcd1234abcd1234abcd1234</code> </p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>Defines the type of log that the source is sending. For valid values for this parameter, see the documentation for the source service.</p>
    pub log_type: ::std::option::Option<::std::string::String>,
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PutDeliverySourceInput {
    /// <p>A name for this delivery source. This name must be unique for all delivery sources in your account.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the Amazon Web Services resource that is generating and sending logs. For example, <code>arn:aws:workmail:us-east-1:123456789012:organization/m-1234EXAMPLEabcd1234abcd1234abcd1234</code> </p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>Defines the type of log that the source is sending. For valid values for this parameter, see the documentation for the source service.</p>
    pub fn log_type(&self) -> ::std::option::Option<&str> {
        self.log_type.as_deref()
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl PutDeliverySourceInput {
    /// Creates a new builder-style object to manufacture [`PutDeliverySourceInput`](crate::operation::put_delivery_source::PutDeliverySourceInput).
    pub fn builder() -> crate::operation::put_delivery_source::builders::PutDeliverySourceInputBuilder {
        crate::operation::put_delivery_source::builders::PutDeliverySourceInputBuilder::default()
    }
}

/// A builder for [`PutDeliverySourceInput`](crate::operation::put_delivery_source::PutDeliverySourceInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct PutDeliverySourceInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) log_type: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PutDeliverySourceInputBuilder {
    /// <p>A name for this delivery source. This name must be unique for all delivery sources in your account.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for this delivery source. This name must be unique for all delivery sources in your account.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for this delivery source. This name must be unique for all delivery sources in your account.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the Amazon Web Services resource that is generating and sending logs. For example, <code>arn:aws:workmail:us-east-1:123456789012:organization/m-1234EXAMPLEabcd1234abcd1234abcd1234</code> </p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Amazon Web Services resource that is generating and sending logs. For example, <code>arn:aws:workmail:us-east-1:123456789012:organization/m-1234EXAMPLEabcd1234abcd1234abcd1234</code> </p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The ARN of the Amazon Web Services resource that is generating and sending logs. For example, <code>arn:aws:workmail:us-east-1:123456789012:organization/m-1234EXAMPLEabcd1234abcd1234abcd1234</code> </p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>Defines the type of log that the source is sending. For valid values for this parameter, see the documentation for the source service.</p>
    /// This field is required.
    pub fn log_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Defines the type of log that the source is sending. For valid values for this parameter, see the documentation for the source service.</p>
    pub fn set_log_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_type = input;
        self
    }
    /// <p>Defines the type of log that the source is sending. For valid values for this parameter, see the documentation for the source service.</p>
    pub fn get_log_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_type
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`PutDeliverySourceInput`](crate::operation::put_delivery_source::PutDeliverySourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_delivery_source::PutDeliverySourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_delivery_source::PutDeliverySourceInput {
            name: self.name,
            resource_arn: self.resource_arn,
            log_type: self.log_type,
            tags: self.tags,
        })
    }
}