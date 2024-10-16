// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the cross-origin access configuration for objects in an Amazon S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html">Enabling Cross-Origin Resource Sharing</a> in the <i>Amazon S3 User Guide</i>.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CorsConfiguration {
    /// <p>A set of origins and methods (cross-origin access that you want to allow). You can add up to 100 rules to the configuration.</p>
    pub cors_rules: ::std::vec::Vec<crate::types::CorsRule>,
}
impl CorsConfiguration {
    /// <p>A set of origins and methods (cross-origin access that you want to allow). You can add up to 100 rules to the configuration.</p>
    pub fn cors_rules(&self) -> &[crate::types::CorsRule] {
        use std::ops::Deref;
        self.cors_rules.deref()
    }
}
impl CorsConfiguration {
    /// Creates a new builder-style object to manufacture [`CorsConfiguration`](crate::types::CorsConfiguration).
    pub fn builder() -> crate::types::builders::CorsConfigurationBuilder {
        crate::types::builders::CorsConfigurationBuilder::default()
    }
}

/// A builder for [`CorsConfiguration`](crate::types::CorsConfiguration).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct CorsConfigurationBuilder {
    pub(crate) cors_rules: ::std::option::Option<::std::vec::Vec<crate::types::CorsRule>>,
}
impl CorsConfigurationBuilder {
    /// Appends an item to `cors_rules`.
    ///
    /// To override the contents of this collection use [`set_cors_rules`](Self::set_cors_rules).
    ///
    /// <p>A set of origins and methods (cross-origin access that you want to allow). You can add up to 100 rules to the configuration.</p>
    pub fn cors_rules(mut self, input: crate::types::CorsRule) -> Self {
        let mut v = self.cors_rules.unwrap_or_default();
        v.push(input);
        self.cors_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of origins and methods (cross-origin access that you want to allow). You can add up to 100 rules to the configuration.</p>
    pub fn set_cors_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CorsRule>>) -> Self {
        self.cors_rules = input;
        self
    }
    /// <p>A set of origins and methods (cross-origin access that you want to allow). You can add up to 100 rules to the configuration.</p>
    pub fn get_cors_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CorsRule>> {
        &self.cors_rules
    }
    /// Consumes the builder and constructs a [`CorsConfiguration`](crate::types::CorsConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`cors_rules`](crate::types::builders::CorsConfigurationBuilder::cors_rules)
    pub fn build(self) -> ::std::result::Result<crate::types::CorsConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CorsConfiguration {
            cors_rules: self.cors_rules.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "cors_rules",
                    "cors_rules was not specified but it is required when building CorsConfiguration",
                )
            })?,
        })
    }
}