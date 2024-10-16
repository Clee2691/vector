// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the SAML application configuration for the domain.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SamlOptionsInput {
    /// <p>True if SAML is enabled.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>Specifies the SAML Identity Provider's information.</p>
    pub idp: ::std::option::Option<crate::types::SamlIdp>,
    /// <p>The SAML master username, which is stored in the Amazon Elasticsearch Service domain's internal database.</p>
    pub master_user_name: ::std::option::Option<::std::string::String>,
    /// <p>The backend role to which the SAML master user is mapped to.</p>
    pub master_backend_role: ::std::option::Option<::std::string::String>,
    /// <p>The key to use for matching the SAML Subject attribute.</p>
    pub subject_key: ::std::option::Option<::std::string::String>,
    /// <p>The key to use for matching the SAML Roles attribute.</p>
    pub roles_key: ::std::option::Option<::std::string::String>,
    /// <p>The duration, in minutes, after which a user session becomes inactive. Acceptable values are between 1 and 1440, and the default value is 60.</p>
    pub session_timeout_minutes: ::std::option::Option<i32>,
}
impl SamlOptionsInput {
    /// <p>True if SAML is enabled.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>Specifies the SAML Identity Provider's information.</p>
    pub fn idp(&self) -> ::std::option::Option<&crate::types::SamlIdp> {
        self.idp.as_ref()
    }
    /// <p>The SAML master username, which is stored in the Amazon Elasticsearch Service domain's internal database.</p>
    pub fn master_user_name(&self) -> ::std::option::Option<&str> {
        self.master_user_name.as_deref()
    }
    /// <p>The backend role to which the SAML master user is mapped to.</p>
    pub fn master_backend_role(&self) -> ::std::option::Option<&str> {
        self.master_backend_role.as_deref()
    }
    /// <p>The key to use for matching the SAML Subject attribute.</p>
    pub fn subject_key(&self) -> ::std::option::Option<&str> {
        self.subject_key.as_deref()
    }
    /// <p>The key to use for matching the SAML Roles attribute.</p>
    pub fn roles_key(&self) -> ::std::option::Option<&str> {
        self.roles_key.as_deref()
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive. Acceptable values are between 1 and 1440, and the default value is 60.</p>
    pub fn session_timeout_minutes(&self) -> ::std::option::Option<i32> {
        self.session_timeout_minutes
    }
}
impl ::std::fmt::Debug for SamlOptionsInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SamlOptionsInput");
        formatter.field("enabled", &self.enabled);
        formatter.field("idp", &self.idp);
        formatter.field("master_user_name", &"*** Sensitive Data Redacted ***");
        formatter.field("master_backend_role", &self.master_backend_role);
        formatter.field("subject_key", &self.subject_key);
        formatter.field("roles_key", &self.roles_key);
        formatter.field("session_timeout_minutes", &self.session_timeout_minutes);
        formatter.finish()
    }
}
impl SamlOptionsInput {
    /// Creates a new builder-style object to manufacture [`SamlOptionsInput`](crate::types::SamlOptionsInput).
    pub fn builder() -> crate::types::builders::SamlOptionsInputBuilder {
        crate::types::builders::SamlOptionsInputBuilder::default()
    }
}

/// A builder for [`SamlOptionsInput`](crate::types::SamlOptionsInput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
pub struct SamlOptionsInputBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) idp: ::std::option::Option<crate::types::SamlIdp>,
    pub(crate) master_user_name: ::std::option::Option<::std::string::String>,
    pub(crate) master_backend_role: ::std::option::Option<::std::string::String>,
    pub(crate) subject_key: ::std::option::Option<::std::string::String>,
    pub(crate) roles_key: ::std::option::Option<::std::string::String>,
    pub(crate) session_timeout_minutes: ::std::option::Option<i32>,
}
impl SamlOptionsInputBuilder {
    /// <p>True if SAML is enabled.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if SAML is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>True if SAML is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>Specifies the SAML Identity Provider's information.</p>
    pub fn idp(mut self, input: crate::types::SamlIdp) -> Self {
        self.idp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the SAML Identity Provider's information.</p>
    pub fn set_idp(mut self, input: ::std::option::Option<crate::types::SamlIdp>) -> Self {
        self.idp = input;
        self
    }
    /// <p>Specifies the SAML Identity Provider's information.</p>
    pub fn get_idp(&self) -> &::std::option::Option<crate::types::SamlIdp> {
        &self.idp
    }
    /// <p>The SAML master username, which is stored in the Amazon Elasticsearch Service domain's internal database.</p>
    pub fn master_user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SAML master username, which is stored in the Amazon Elasticsearch Service domain's internal database.</p>
    pub fn set_master_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_user_name = input;
        self
    }
    /// <p>The SAML master username, which is stored in the Amazon Elasticsearch Service domain's internal database.</p>
    pub fn get_master_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_user_name
    }
    /// <p>The backend role to which the SAML master user is mapped to.</p>
    pub fn master_backend_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_backend_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The backend role to which the SAML master user is mapped to.</p>
    pub fn set_master_backend_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_backend_role = input;
        self
    }
    /// <p>The backend role to which the SAML master user is mapped to.</p>
    pub fn get_master_backend_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_backend_role
    }
    /// <p>The key to use for matching the SAML Subject attribute.</p>
    pub fn subject_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key to use for matching the SAML Subject attribute.</p>
    pub fn set_subject_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject_key = input;
        self
    }
    /// <p>The key to use for matching the SAML Subject attribute.</p>
    pub fn get_subject_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject_key
    }
    /// <p>The key to use for matching the SAML Roles attribute.</p>
    pub fn roles_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.roles_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key to use for matching the SAML Roles attribute.</p>
    pub fn set_roles_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.roles_key = input;
        self
    }
    /// <p>The key to use for matching the SAML Roles attribute.</p>
    pub fn get_roles_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.roles_key
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive. Acceptable values are between 1 and 1440, and the default value is 60.</p>
    pub fn session_timeout_minutes(mut self, input: i32) -> Self {
        self.session_timeout_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive. Acceptable values are between 1 and 1440, and the default value is 60.</p>
    pub fn set_session_timeout_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.session_timeout_minutes = input;
        self
    }
    /// <p>The duration, in minutes, after which a user session becomes inactive. Acceptable values are between 1 and 1440, and the default value is 60.</p>
    pub fn get_session_timeout_minutes(&self) -> &::std::option::Option<i32> {
        &self.session_timeout_minutes
    }
    /// Consumes the builder and constructs a [`SamlOptionsInput`](crate::types::SamlOptionsInput).
    pub fn build(self) -> crate::types::SamlOptionsInput {
        crate::types::SamlOptionsInput {
            enabled: self.enabled,
            idp: self.idp,
            master_user_name: self.master_user_name,
            master_backend_role: self.master_backend_role,
            subject_key: self.subject_key,
            roles_key: self.roles_key,
            session_timeout_minutes: self.session_timeout_minutes,
        }
    }
}
impl ::std::fmt::Debug for SamlOptionsInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SamlOptionsInputBuilder");
        formatter.field("enabled", &self.enabled);
        formatter.field("idp", &self.idp);
        formatter.field("master_user_name", &"*** Sensitive Data Redacted ***");
        formatter.field("master_backend_role", &self.master_backend_role);
        formatter.field("subject_key", &self.subject_key);
        formatter.field("roles_key", &self.roles_key);
        formatter.field("session_timeout_minutes", &self.session_timeout_minutes);
        formatter.finish()
    }
}