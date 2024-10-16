// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The fields contained in log events found by a <code>GetLogGroupFields</code> operation, along with the percentage of queried log events in which each field appears.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogGroupField {
    /// <p>The name of a log field.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The percentage of log events queried that contained the field.</p>
    pub percent: i32,
}
impl LogGroupField {
    /// <p>The name of a log field.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The percentage of log events queried that contained the field.</p>
    pub fn percent(&self) -> i32 {
        self.percent
    }
}
impl LogGroupField {
    /// Creates a new builder-style object to manufacture [`LogGroupField`](crate::types::LogGroupField).
    pub fn builder() -> crate::types::builders::LogGroupFieldBuilder {
        crate::types::builders::LogGroupFieldBuilder::default()
    }
}

/// A builder for [`LogGroupField`](crate::types::LogGroupField).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct LogGroupFieldBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) percent: ::std::option::Option<i32>,
}
impl LogGroupFieldBuilder {
    /// <p>The name of a log field.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a log field.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a log field.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The percentage of log events queried that contained the field.</p>
    pub fn percent(mut self, input: i32) -> Self {
        self.percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of log events queried that contained the field.</p>
    pub fn set_percent(mut self, input: ::std::option::Option<i32>) -> Self {
        self.percent = input;
        self
    }
    /// <p>The percentage of log events queried that contained the field.</p>
    pub fn get_percent(&self) -> &::std::option::Option<i32> {
        &self.percent
    }
    /// Consumes the builder and constructs a [`LogGroupField`](crate::types::LogGroupField).
    pub fn build(self) -> crate::types::LogGroupField {
        crate::types::LogGroupField {
            name: self.name,
            percent: self.percent.unwrap_or_default(),
        }
    }
}