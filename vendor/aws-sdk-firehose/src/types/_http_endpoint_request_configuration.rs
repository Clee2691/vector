// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of the HTTP endpoint request.</p>
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HttpEndpointRequestConfiguration {
    /// <p>Kinesis Data Firehose uses the content encoding to compress the body of a request before sending the request to the destination. For more information, see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding">Content-Encoding</a> in MDN Web Docs, the official Mozilla documentation.</p>
    pub content_encoding: ::std::option::Option<crate::types::ContentEncoding>,
    /// <p>Describes the metadata sent to the HTTP endpoint destination.</p>
    pub common_attributes: ::std::option::Option<::std::vec::Vec<crate::types::HttpEndpointCommonAttribute>>,
}
impl HttpEndpointRequestConfiguration {
    /// <p>Kinesis Data Firehose uses the content encoding to compress the body of a request before sending the request to the destination. For more information, see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding">Content-Encoding</a> in MDN Web Docs, the official Mozilla documentation.</p>
    pub fn content_encoding(&self) -> ::std::option::Option<&crate::types::ContentEncoding> {
        self.content_encoding.as_ref()
    }
    /// <p>Describes the metadata sent to the HTTP endpoint destination.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.common_attributes.is_none()`.
    pub fn common_attributes(&self) -> &[crate::types::HttpEndpointCommonAttribute] {
        self.common_attributes.as_deref().unwrap_or_default()
    }
}
impl HttpEndpointRequestConfiguration {
    /// Creates a new builder-style object to manufacture [`HttpEndpointRequestConfiguration`](crate::types::HttpEndpointRequestConfiguration).
    pub fn builder() -> crate::types::builders::HttpEndpointRequestConfigurationBuilder {
        crate::types::builders::HttpEndpointRequestConfigurationBuilder::default()
    }
}

/// A builder for [`HttpEndpointRequestConfiguration`](crate::types::HttpEndpointRequestConfiguration).
#[non_exhaustive]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
pub struct HttpEndpointRequestConfigurationBuilder {
    pub(crate) content_encoding: ::std::option::Option<crate::types::ContentEncoding>,
    pub(crate) common_attributes: ::std::option::Option<::std::vec::Vec<crate::types::HttpEndpointCommonAttribute>>,
}
impl HttpEndpointRequestConfigurationBuilder {
    /// <p>Kinesis Data Firehose uses the content encoding to compress the body of a request before sending the request to the destination. For more information, see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding">Content-Encoding</a> in MDN Web Docs, the official Mozilla documentation.</p>
    pub fn content_encoding(mut self, input: crate::types::ContentEncoding) -> Self {
        self.content_encoding = ::std::option::Option::Some(input);
        self
    }
    /// <p>Kinesis Data Firehose uses the content encoding to compress the body of a request before sending the request to the destination. For more information, see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding">Content-Encoding</a> in MDN Web Docs, the official Mozilla documentation.</p>
    pub fn set_content_encoding(mut self, input: ::std::option::Option<crate::types::ContentEncoding>) -> Self {
        self.content_encoding = input;
        self
    }
    /// <p>Kinesis Data Firehose uses the content encoding to compress the body of a request before sending the request to the destination. For more information, see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding">Content-Encoding</a> in MDN Web Docs, the official Mozilla documentation.</p>
    pub fn get_content_encoding(&self) -> &::std::option::Option<crate::types::ContentEncoding> {
        &self.content_encoding
    }
    /// Appends an item to `common_attributes`.
    ///
    /// To override the contents of this collection use [`set_common_attributes`](Self::set_common_attributes).
    ///
    /// <p>Describes the metadata sent to the HTTP endpoint destination.</p>
    pub fn common_attributes(mut self, input: crate::types::HttpEndpointCommonAttribute) -> Self {
        let mut v = self.common_attributes.unwrap_or_default();
        v.push(input);
        self.common_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the metadata sent to the HTTP endpoint destination.</p>
    pub fn set_common_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HttpEndpointCommonAttribute>>) -> Self {
        self.common_attributes = input;
        self
    }
    /// <p>Describes the metadata sent to the HTTP endpoint destination.</p>
    pub fn get_common_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HttpEndpointCommonAttribute>> {
        &self.common_attributes
    }
    /// Consumes the builder and constructs a [`HttpEndpointRequestConfiguration`](crate::types::HttpEndpointRequestConfiguration).
    pub fn build(self) -> crate::types::HttpEndpointRequestConfiguration {
        crate::types::HttpEndpointRequestConfiguration {
            content_encoding: self.content_encoding,
            common_attributes: self.common_attributes,
        }
    }
}