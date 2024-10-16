// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for restore job parameters.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestoreRequest {
    /// <p>Lifetime of the active copy in days. Do not use with restores that specify <code>OutputLocation</code>.</p>
    /// <p>The Days element is required for regular restores, and must not be provided for select requests.</p>
    pub days: ::std::option::Option<i32>,
    /// <p>S3 Glacier related parameters pertaining to this job. Do not use with restores that specify <code>OutputLocation</code>.</p>
    pub glacier_job_parameters: ::std::option::Option<crate::types::GlacierJobParameters>,
    /// <p>Type of restore request.</p>
    pub r#type: ::std::option::Option<crate::types::RestoreRequestType>,
    /// <p>Retrieval tier at which the restore will be processed.</p>
    pub tier: ::std::option::Option<crate::types::Tier>,
    /// <p>The optional description for the job.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Describes the parameters for Select job types.</p>
    pub select_parameters: ::std::option::Option<crate::types::SelectParameters>,
    /// <p>Describes the location where the restore job's output is stored.</p>
    pub output_location: ::std::option::Option<crate::types::OutputLocation>,
}
impl RestoreRequest {
    /// <p>Lifetime of the active copy in days. Do not use with restores that specify <code>OutputLocation</code>.</p>
    /// <p>The Days element is required for regular restores, and must not be provided for select requests.</p>
    pub fn days(&self) -> ::std::option::Option<i32> {
        self.days
    }
    /// <p>S3 Glacier related parameters pertaining to this job. Do not use with restores that specify <code>OutputLocation</code>.</p>
    pub fn glacier_job_parameters(&self) -> ::std::option::Option<&crate::types::GlacierJobParameters> {
        self.glacier_job_parameters.as_ref()
    }
    /// <p>Type of restore request.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::RestoreRequestType> {
        self.r#type.as_ref()
    }
    /// <p>Retrieval tier at which the restore will be processed.</p>
    pub fn tier(&self) -> ::std::option::Option<&crate::types::Tier> {
        self.tier.as_ref()
    }
    /// <p>The optional description for the job.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Describes the parameters for Select job types.</p>
    pub fn select_parameters(&self) -> ::std::option::Option<&crate::types::SelectParameters> {
        self.select_parameters.as_ref()
    }
    /// <p>Describes the location where the restore job's output is stored.</p>
    pub fn output_location(&self) -> ::std::option::Option<&crate::types::OutputLocation> {
        self.output_location.as_ref()
    }
}
impl RestoreRequest {
    /// Creates a new builder-style object to manufacture [`RestoreRequest`](crate::types::RestoreRequest).
    pub fn builder() -> crate::types::builders::RestoreRequestBuilder {
        crate::types::builders::RestoreRequestBuilder::default()
    }
}

/// A builder for [`RestoreRequest`](crate::types::RestoreRequest).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct RestoreRequestBuilder {
    pub(crate) days: ::std::option::Option<i32>,
    pub(crate) glacier_job_parameters: ::std::option::Option<crate::types::GlacierJobParameters>,
    pub(crate) r#type: ::std::option::Option<crate::types::RestoreRequestType>,
    pub(crate) tier: ::std::option::Option<crate::types::Tier>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) select_parameters: ::std::option::Option<crate::types::SelectParameters>,
    pub(crate) output_location: ::std::option::Option<crate::types::OutputLocation>,
}
impl RestoreRequestBuilder {
    /// <p>Lifetime of the active copy in days. Do not use with restores that specify <code>OutputLocation</code>.</p>
    /// <p>The Days element is required for regular restores, and must not be provided for select requests.</p>
    pub fn days(mut self, input: i32) -> Self {
        self.days = ::std::option::Option::Some(input);
        self
    }
    /// <p>Lifetime of the active copy in days. Do not use with restores that specify <code>OutputLocation</code>.</p>
    /// <p>The Days element is required for regular restores, and must not be provided for select requests.</p>
    pub fn set_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.days = input;
        self
    }
    /// <p>Lifetime of the active copy in days. Do not use with restores that specify <code>OutputLocation</code>.</p>
    /// <p>The Days element is required for regular restores, and must not be provided for select requests.</p>
    pub fn get_days(&self) -> &::std::option::Option<i32> {
        &self.days
    }
    /// <p>S3 Glacier related parameters pertaining to this job. Do not use with restores that specify <code>OutputLocation</code>.</p>
    pub fn glacier_job_parameters(mut self, input: crate::types::GlacierJobParameters) -> Self {
        self.glacier_job_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>S3 Glacier related parameters pertaining to this job. Do not use with restores that specify <code>OutputLocation</code>.</p>
    pub fn set_glacier_job_parameters(mut self, input: ::std::option::Option<crate::types::GlacierJobParameters>) -> Self {
        self.glacier_job_parameters = input;
        self
    }
    /// <p>S3 Glacier related parameters pertaining to this job. Do not use with restores that specify <code>OutputLocation</code>.</p>
    pub fn get_glacier_job_parameters(&self) -> &::std::option::Option<crate::types::GlacierJobParameters> {
        &self.glacier_job_parameters
    }
    /// <p>Type of restore request.</p>
    pub fn r#type(mut self, input: crate::types::RestoreRequestType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of restore request.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RestoreRequestType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of restore request.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RestoreRequestType> {
        &self.r#type
    }
    /// <p>Retrieval tier at which the restore will be processed.</p>
    pub fn tier(mut self, input: crate::types::Tier) -> Self {
        self.tier = ::std::option::Option::Some(input);
        self
    }
    /// <p>Retrieval tier at which the restore will be processed.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<crate::types::Tier>) -> Self {
        self.tier = input;
        self
    }
    /// <p>Retrieval tier at which the restore will be processed.</p>
    pub fn get_tier(&self) -> &::std::option::Option<crate::types::Tier> {
        &self.tier
    }
    /// <p>The optional description for the job.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The optional description for the job.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The optional description for the job.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Describes the parameters for Select job types.</p>
    pub fn select_parameters(mut self, input: crate::types::SelectParameters) -> Self {
        self.select_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the parameters for Select job types.</p>
    pub fn set_select_parameters(mut self, input: ::std::option::Option<crate::types::SelectParameters>) -> Self {
        self.select_parameters = input;
        self
    }
    /// <p>Describes the parameters for Select job types.</p>
    pub fn get_select_parameters(&self) -> &::std::option::Option<crate::types::SelectParameters> {
        &self.select_parameters
    }
    /// <p>Describes the location where the restore job's output is stored.</p>
    pub fn output_location(mut self, input: crate::types::OutputLocation) -> Self {
        self.output_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the location where the restore job's output is stored.</p>
    pub fn set_output_location(mut self, input: ::std::option::Option<crate::types::OutputLocation>) -> Self {
        self.output_location = input;
        self
    }
    /// <p>Describes the location where the restore job's output is stored.</p>
    pub fn get_output_location(&self) -> &::std::option::Option<crate::types::OutputLocation> {
        &self.output_location
    }
    /// Consumes the builder and constructs a [`RestoreRequest`](crate::types::RestoreRequest).
    pub fn build(self) -> crate::types::RestoreRequest {
        crate::types::RestoreRequest {
            days: self.days,
            glacier_job_parameters: self.glacier_job_parameters,
            r#type: self.r#type,
            tier: self.tier,
            description: self.description,
            select_parameters: self.select_parameters,
            output_location: self.output_location,
        }
    }
}