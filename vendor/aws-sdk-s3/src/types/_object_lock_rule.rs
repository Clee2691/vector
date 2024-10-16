// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The container element for an Object Lock rule.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectLockRule {
    /// <p>The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket. Bucket settings require both a mode and a period. The period can be either <code>Days</code> or <code>Years</code> but you must select one. You cannot specify <code>Days</code> and <code>Years</code> at the same time.</p>
    pub default_retention: ::std::option::Option<crate::types::DefaultRetention>,
}
impl ObjectLockRule {
    /// <p>The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket. Bucket settings require both a mode and a period. The period can be either <code>Days</code> or <code>Years</code> but you must select one. You cannot specify <code>Days</code> and <code>Years</code> at the same time.</p>
    pub fn default_retention(&self) -> ::std::option::Option<&crate::types::DefaultRetention> {
        self.default_retention.as_ref()
    }
}
impl ObjectLockRule {
    /// Creates a new builder-style object to manufacture [`ObjectLockRule`](crate::types::ObjectLockRule).
    pub fn builder() -> crate::types::builders::ObjectLockRuleBuilder {
        crate::types::builders::ObjectLockRuleBuilder::default()
    }
}

/// A builder for [`ObjectLockRule`](crate::types::ObjectLockRule).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ObjectLockRuleBuilder {
    pub(crate) default_retention: ::std::option::Option<crate::types::DefaultRetention>,
}
impl ObjectLockRuleBuilder {
    /// <p>The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket. Bucket settings require both a mode and a period. The period can be either <code>Days</code> or <code>Years</code> but you must select one. You cannot specify <code>Days</code> and <code>Years</code> at the same time.</p>
    pub fn default_retention(mut self, input: crate::types::DefaultRetention) -> Self {
        self.default_retention = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket. Bucket settings require both a mode and a period. The period can be either <code>Days</code> or <code>Years</code> but you must select one. You cannot specify <code>Days</code> and <code>Years</code> at the same time.</p>
    pub fn set_default_retention(mut self, input: ::std::option::Option<crate::types::DefaultRetention>) -> Self {
        self.default_retention = input;
        self
    }
    /// <p>The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket. Bucket settings require both a mode and a period. The period can be either <code>Days</code> or <code>Years</code> but you must select one. You cannot specify <code>Days</code> and <code>Years</code> at the same time.</p>
    pub fn get_default_retention(&self) -> &::std::option::Option<crate::types::DefaultRetention> {
        &self.default_retention
    }
    /// Consumes the builder and constructs a [`ObjectLockRule`](crate::types::ObjectLockRule).
    pub fn build(self) -> crate::types::ObjectLockRule {
        crate::types::ObjectLockRule {
            default_retention: self.default_retention,
        }
    }
}