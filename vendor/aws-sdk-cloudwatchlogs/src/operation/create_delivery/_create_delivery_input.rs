// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDeliveryInput {
    /// <p>The name of the delivery source to use for this delivery.</p>
    pub delivery_source_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the delivery destination to use for this delivery.</p>
    pub delivery_destination_arn: ::std::option::Option<::std::string::String>,
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDeliveryInput {
    /// <p>The name of the delivery source to use for this delivery.</p>
    pub fn delivery_source_name(&self) -> ::std::option::Option<&str> {
        self.delivery_source_name.as_deref()
    }
    /// <p>The ARN of the delivery destination to use for this delivery.</p>
    pub fn delivery_destination_arn(&self) -> ::std::option::Option<&str> {
        self.delivery_destination_arn.as_deref()
    }
    /// <p>An optional list of key-value pairs to associate with the resource.</p>
    /// <p>For more information about tagging, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> </p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateDeliveryInput {
    /// Creates a new builder-style object to manufacture [`CreateDeliveryInput`](crate::operation::create_delivery::CreateDeliveryInput).
    pub fn builder() -> crate::operation::create_delivery::builders::CreateDeliveryInputBuilder {
        crate::operation::create_delivery::builders::CreateDeliveryInputBuilder::default()
    }
}

/// A builder for [`CreateDeliveryInput`](crate::operation::create_delivery::CreateDeliveryInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct CreateDeliveryInputBuilder {
    pub(crate) delivery_source_name: ::std::option::Option<::std::string::String>,
    pub(crate) delivery_destination_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDeliveryInputBuilder {
    /// <p>The name of the delivery source to use for this delivery.</p>
    /// This field is required.
    pub fn delivery_source_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_source_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the delivery source to use for this delivery.</p>
    pub fn set_delivery_source_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_source_name = input;
        self
    }
    /// <p>The name of the delivery source to use for this delivery.</p>
    pub fn get_delivery_source_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_source_name
    }
    /// <p>The ARN of the delivery destination to use for this delivery.</p>
    /// This field is required.
    pub fn delivery_destination_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_destination_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the delivery destination to use for this delivery.</p>
    pub fn set_delivery_destination_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_destination_arn = input;
        self
    }
    /// <p>The ARN of the delivery destination to use for this delivery.</p>
    pub fn get_delivery_destination_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_destination_arn
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
    /// Consumes the builder and constructs a [`CreateDeliveryInput`](crate::operation::create_delivery::CreateDeliveryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_delivery::CreateDeliveryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_delivery::CreateDeliveryInput {
            delivery_source_name: self.delivery_source_name,
            delivery_destination_arn: self.delivery_destination_arn,
            tags: self.tags,
        })
    }
}