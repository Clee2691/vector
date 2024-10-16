// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Response for GetPlatformApplicationAttributes action.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPlatformApplicationAttributesOutput {
    /// <p>Attributes include the following:</p>
    /// <ul>
    /// <li> <p> <code>AppleCertificateExpiryDate</code> – The expiry date of the SSL certificate used to configure certificate-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformTeamID</code> – The Apple developer account ID used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformBundleID</code> – The app identifier used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>EventEndpointCreated</code> – Topic ARN to which EndpointCreated event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointDeleted</code> – Topic ARN to which EndpointDeleted event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointUpdated</code> – Topic ARN to which EndpointUpdate event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventDeliveryFailure</code> – Topic ARN to which DeliveryFailure event notifications should be sent upon Direct Publish delivery failure (permanent) to one of the application's endpoints.</p> </li>
    /// </ul>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetPlatformApplicationAttributesOutput {
    /// <p>Attributes include the following:</p>
    /// <ul>
    /// <li> <p> <code>AppleCertificateExpiryDate</code> – The expiry date of the SSL certificate used to configure certificate-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformTeamID</code> – The Apple developer account ID used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformBundleID</code> – The app identifier used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>EventEndpointCreated</code> – Topic ARN to which EndpointCreated event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointDeleted</code> – Topic ARN to which EndpointDeleted event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointUpdated</code> – Topic ARN to which EndpointUpdate event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventDeliveryFailure</code> – Topic ARN to which DeliveryFailure event notifications should be sent upon Direct Publish delivery failure (permanent) to one of the application's endpoints.</p> </li>
    /// </ul>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetPlatformApplicationAttributesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPlatformApplicationAttributesOutput {
    /// Creates a new builder-style object to manufacture [`GetPlatformApplicationAttributesOutput`](crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesOutput).
    pub fn builder() -> crate::operation::get_platform_application_attributes::builders::GetPlatformApplicationAttributesOutputBuilder {
        crate::operation::get_platform_application_attributes::builders::GetPlatformApplicationAttributesOutputBuilder::default()
    }
}

/// A builder for [`GetPlatformApplicationAttributesOutput`](crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesOutput).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct GetPlatformApplicationAttributesOutputBuilder {
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetPlatformApplicationAttributesOutputBuilder {
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>Attributes include the following:</p>
    /// <ul>
    /// <li> <p> <code>AppleCertificateExpiryDate</code> – The expiry date of the SSL certificate used to configure certificate-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformTeamID</code> – The Apple developer account ID used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformBundleID</code> – The app identifier used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>EventEndpointCreated</code> – Topic ARN to which EndpointCreated event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointDeleted</code> – Topic ARN to which EndpointDeleted event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointUpdated</code> – Topic ARN to which EndpointUpdate event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventDeliveryFailure</code> – Topic ARN to which DeliveryFailure event notifications should be sent upon Direct Publish delivery failure (permanent) to one of the application's endpoints.</p> </li>
    /// </ul>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Attributes include the following:</p>
    /// <ul>
    /// <li> <p> <code>AppleCertificateExpiryDate</code> – The expiry date of the SSL certificate used to configure certificate-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformTeamID</code> – The Apple developer account ID used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformBundleID</code> – The app identifier used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>EventEndpointCreated</code> – Topic ARN to which EndpointCreated event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointDeleted</code> – Topic ARN to which EndpointDeleted event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointUpdated</code> – Topic ARN to which EndpointUpdate event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventDeliveryFailure</code> – Topic ARN to which DeliveryFailure event notifications should be sent upon Direct Publish delivery failure (permanent) to one of the application's endpoints.</p> </li>
    /// </ul>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>Attributes include the following:</p>
    /// <ul>
    /// <li> <p> <code>AppleCertificateExpiryDate</code> – The expiry date of the SSL certificate used to configure certificate-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformTeamID</code> – The Apple developer account ID used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>ApplePlatformBundleID</code> – The app identifier used to configure token-based authentication.</p> </li>
    /// <li> <p> <code>EventEndpointCreated</code> – Topic ARN to which EndpointCreated event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointDeleted</code> – Topic ARN to which EndpointDeleted event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventEndpointUpdated</code> – Topic ARN to which EndpointUpdate event notifications should be sent.</p> </li>
    /// <li> <p> <code>EventDeliveryFailure</code> – Topic ARN to which DeliveryFailure event notifications should be sent upon Direct Publish delivery failure (permanent) to one of the application's endpoints.</p> </li>
    /// </ul>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPlatformApplicationAttributesOutput`](crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesOutput).
    pub fn build(self) -> crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesOutput {
        crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesOutput {
            attributes: self.attributes,
            _request_id: self._request_id,
        }
    }
}