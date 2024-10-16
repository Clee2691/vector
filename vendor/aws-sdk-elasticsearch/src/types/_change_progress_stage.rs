// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A progress stage details of a specific domain configuration change.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChangeProgressStage {
    /// <p>The name of the specific progress stage.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The overall status of a specific progress stage.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The description of the progress stage.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The last updated timestamp of the progress stage.</p>
    pub last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ChangeProgressStage {
    /// <p>The name of the specific progress stage.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The overall status of a specific progress stage.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The description of the progress stage.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The last updated timestamp of the progress stage.</p>
    pub fn last_updated(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated.as_ref()
    }
}
impl ChangeProgressStage {
    /// Creates a new builder-style object to manufacture [`ChangeProgressStage`](crate::types::ChangeProgressStage).
    pub fn builder() -> crate::types::builders::ChangeProgressStageBuilder {
        crate::types::builders::ChangeProgressStageBuilder::default()
    }
}

/// A builder for [`ChangeProgressStage`](crate::types::ChangeProgressStage).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ChangeProgressStageBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ChangeProgressStageBuilder {
    /// <p>The name of the specific progress stage.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the specific progress stage.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the specific progress stage.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The overall status of a specific progress stage.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The overall status of a specific progress stage.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The overall status of a specific progress stage.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The description of the progress stage.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the progress stage.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the progress stage.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The last updated timestamp of the progress stage.</p>
    pub fn last_updated(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last updated timestamp of the progress stage.</p>
    pub fn set_last_updated(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated = input;
        self
    }
    /// <p>The last updated timestamp of the progress stage.</p>
    pub fn get_last_updated(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated
    }
    /// Consumes the builder and constructs a [`ChangeProgressStage`](crate::types::ChangeProgressStage).
    pub fn build(self) -> crate::types::ChangeProgressStage {
        crate::types::ChangeProgressStage {
            name: self.name,
            status: self.status,
            description: self.description,
            last_updated: self.last_updated,
        }
    }
}