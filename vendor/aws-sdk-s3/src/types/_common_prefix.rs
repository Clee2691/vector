// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for all (if there are any) keys between Prefix and the next occurrence of the string specified by a delimiter. CommonPrefixes lists keys that act like subdirectories in the directory specified by Prefix. For example, if the prefix is notes/ and the delimiter is a slash (/) as in notes/summer/july, the common prefix is notes/summer/. </p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CommonPrefix {
    /// <p>Container for the specified common prefix.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
}
impl CommonPrefix {
    /// <p>Container for the specified common prefix.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
}
impl CommonPrefix {
    /// Creates a new builder-style object to manufacture [`CommonPrefix`](crate::types::CommonPrefix).
    pub fn builder() -> crate::types::builders::CommonPrefixBuilder {
        crate::types::builders::CommonPrefixBuilder::default()
    }
}

/// A builder for [`CommonPrefix`](crate::types::CommonPrefix).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct CommonPrefixBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
}
impl CommonPrefixBuilder {
    /// <p>Container for the specified common prefix.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Container for the specified common prefix.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>Container for the specified common prefix.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Consumes the builder and constructs a [`CommonPrefix`](crate::types::CommonPrefix).
    pub fn build(self) -> crate::types::CommonPrefix {
        crate::types::CommonPrefix { prefix: self.prefix }
    }
}