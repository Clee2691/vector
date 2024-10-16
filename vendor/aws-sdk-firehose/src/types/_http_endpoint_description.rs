// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the HTTP endpoint selected as the destination. </p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct HttpEndpointDescription {
    /// <p>The URL of the HTTP endpoint selected as the destination.</p>
    pub url: ::std::option::Option<::std::string::String>,
    /// <p>The name of the HTTP endpoint selected as the destination.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl HttpEndpointDescription {
    /// <p>The URL of the HTTP endpoint selected as the destination.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
    /// <p>The name of the HTTP endpoint selected as the destination.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ::std::fmt::Debug for HttpEndpointDescription {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("HttpEndpointDescription");
        formatter.field("url", &"*** Sensitive Data Redacted ***");
        formatter.field("name", &self.name);
        formatter.finish()
    }
}
impl HttpEndpointDescription {
    /// Creates a new builder-style object to manufacture [`HttpEndpointDescription`](crate::types::HttpEndpointDescription).
    pub fn builder() -> crate::types::builders::HttpEndpointDescriptionBuilder {
        crate::types::builders::HttpEndpointDescriptionBuilder::default()
    }
}

/// A builder for [`HttpEndpointDescription`](crate::types::HttpEndpointDescription).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
pub struct HttpEndpointDescriptionBuilder {
    pub(crate) url: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl HttpEndpointDescriptionBuilder {
    /// <p>The URL of the HTTP endpoint selected as the destination.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the HTTP endpoint selected as the destination.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL of the HTTP endpoint selected as the destination.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// <p>The name of the HTTP endpoint selected as the destination.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the HTTP endpoint selected as the destination.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the HTTP endpoint selected as the destination.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`HttpEndpointDescription`](crate::types::HttpEndpointDescription).
    pub fn build(self) -> crate::types::HttpEndpointDescription {
        crate::types::HttpEndpointDescription {
            url: self.url,
            name: self.name,
        }
    }
}
impl ::std::fmt::Debug for HttpEndpointDescriptionBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("HttpEndpointDescriptionBuilder");
        formatter.field("url", &"*** Sensitive Data Redacted ***");
        formatter.field("name", &self.name);
        formatter.finish()
    }
}