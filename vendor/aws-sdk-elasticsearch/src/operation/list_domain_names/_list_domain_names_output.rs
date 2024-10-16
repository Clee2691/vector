// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code>ListDomainNames</code> operation. Contains the names of all domains owned by this account and their respective engine types.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDomainNamesOutput {
    /// <p>List of domain names and respective engine types.</p>
    pub domain_names: ::std::option::Option<::std::vec::Vec<crate::types::DomainInfo>>,
    _request_id: Option<String>,
}
impl ListDomainNamesOutput {
    /// <p>List of domain names and respective engine types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domain_names.is_none()`.
    pub fn domain_names(&self) -> &[crate::types::DomainInfo] {
        self.domain_names.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListDomainNamesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDomainNamesOutput {
    /// Creates a new builder-style object to manufacture [`ListDomainNamesOutput`](crate::operation::list_domain_names::ListDomainNamesOutput).
    pub fn builder() -> crate::operation::list_domain_names::builders::ListDomainNamesOutputBuilder {
        crate::operation::list_domain_names::builders::ListDomainNamesOutputBuilder::default()
    }
}

/// A builder for [`ListDomainNamesOutput`](crate::operation::list_domain_names::ListDomainNamesOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct ListDomainNamesOutputBuilder {
    pub(crate) domain_names: ::std::option::Option<::std::vec::Vec<crate::types::DomainInfo>>,
    _request_id: Option<String>,
}
impl ListDomainNamesOutputBuilder {
    /// Appends an item to `domain_names`.
    ///
    /// To override the contents of this collection use [`set_domain_names`](Self::set_domain_names).
    ///
    /// <p>List of domain names and respective engine types.</p>
    pub fn domain_names(mut self, input: crate::types::DomainInfo) -> Self {
        let mut v = self.domain_names.unwrap_or_default();
        v.push(input);
        self.domain_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of domain names and respective engine types.</p>
    pub fn set_domain_names(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DomainInfo>>) -> Self {
        self.domain_names = input;
        self
    }
    /// <p>List of domain names and respective engine types.</p>
    pub fn get_domain_names(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DomainInfo>> {
        &self.domain_names
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDomainNamesOutput`](crate::operation::list_domain_names::ListDomainNamesOutput).
    pub fn build(self) -> crate::operation::list_domain_names::ListDomainNamesOutput {
        crate::operation::list_domain_names::ListDomainNamesOutput {
            domain_names: self.domain_names,
            _request_id: self._request_id,
        }
    }
}