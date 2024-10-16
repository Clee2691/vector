// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the metadata that's delivered to the specified HTTP endpoint destination.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct HttpEndpointCommonAttribute {
    /// <p>The name of the HTTP endpoint common attribute.</p>
    pub attribute_name: ::std::string::String,
    /// <p>The value of the HTTP endpoint common attribute.</p>
    pub attribute_value: ::std::string::String,
}
impl HttpEndpointCommonAttribute {
    /// <p>The name of the HTTP endpoint common attribute.</p>
    pub fn attribute_name(&self) -> &str {
        use std::ops::Deref;
        self.attribute_name.deref()
    }
    /// <p>The value of the HTTP endpoint common attribute.</p>
    pub fn attribute_value(&self) -> &str {
        use std::ops::Deref;
        self.attribute_value.deref()
    }
}
impl ::std::fmt::Debug for HttpEndpointCommonAttribute {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("HttpEndpointCommonAttribute");
        formatter.field("attribute_name", &"*** Sensitive Data Redacted ***");
        formatter.field("attribute_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl HttpEndpointCommonAttribute {
    /// Creates a new builder-style object to manufacture [`HttpEndpointCommonAttribute`](crate::types::HttpEndpointCommonAttribute).
    pub fn builder() -> crate::types::builders::HttpEndpointCommonAttributeBuilder {
        crate::types::builders::HttpEndpointCommonAttributeBuilder::default()
    }
}

/// A builder for [`HttpEndpointCommonAttribute`](crate::types::HttpEndpointCommonAttribute).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
pub struct HttpEndpointCommonAttributeBuilder {
    pub(crate) attribute_name: ::std::option::Option<::std::string::String>,
    pub(crate) attribute_value: ::std::option::Option<::std::string::String>,
}
impl HttpEndpointCommonAttributeBuilder {
    /// <p>The name of the HTTP endpoint common attribute.</p>
    /// This field is required.
    pub fn attribute_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the HTTP endpoint common attribute.</p>
    pub fn set_attribute_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute_name = input;
        self
    }
    /// <p>The name of the HTTP endpoint common attribute.</p>
    pub fn get_attribute_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute_name
    }
    /// <p>The value of the HTTP endpoint common attribute.</p>
    /// This field is required.
    pub fn attribute_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the HTTP endpoint common attribute.</p>
    pub fn set_attribute_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute_value = input;
        self
    }
    /// <p>The value of the HTTP endpoint common attribute.</p>
    pub fn get_attribute_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute_value
    }
    /// Consumes the builder and constructs a [`HttpEndpointCommonAttribute`](crate::types::HttpEndpointCommonAttribute).
    /// This method will fail if any of the following fields are not set:
    /// - [`attribute_name`](crate::types::builders::HttpEndpointCommonAttributeBuilder::attribute_name)
    /// - [`attribute_value`](crate::types::builders::HttpEndpointCommonAttributeBuilder::attribute_value)
    pub fn build(self) -> ::std::result::Result<crate::types::HttpEndpointCommonAttribute, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::HttpEndpointCommonAttribute {
            attribute_name: self.attribute_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute_name",
                    "attribute_name was not specified but it is required when building HttpEndpointCommonAttribute",
                )
            })?,
            attribute_value: self.attribute_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute_value",
                    "attribute_value was not specified but it is required when building HttpEndpointCommonAttribute",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for HttpEndpointCommonAttributeBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("HttpEndpointCommonAttributeBuilder");
        formatter.field("attribute_name", &"*** Sensitive Data Redacted ***");
        formatter.field("attribute_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}