// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `VpcEndpointStatus`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let vpcendpointstatus = unimplemented!();
/// match vpcendpointstatus {
///     VpcEndpointStatus::Active => { /* ... */ },
///     VpcEndpointStatus::CreateFailed => { /* ... */ },
///     VpcEndpointStatus::Creating => { /* ... */ },
///     VpcEndpointStatus::DeleteFailed => { /* ... */ },
///     VpcEndpointStatus::Deleting => { /* ... */ },
///     VpcEndpointStatus::UpdateFailed => { /* ... */ },
///     VpcEndpointStatus::Updating => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `vpcendpointstatus` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `VpcEndpointStatus::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `VpcEndpointStatus::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `VpcEndpointStatus::NewFeature` is defined.
/// Specifically, when `vpcendpointstatus` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `VpcEndpointStatus::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
/// <p>Specifies the current status of the VPC endpoint:
/// <ul>
/// <li>CREATING: Indicates that the VPC endpoint is currently being created.</li>
/// <li>CREATE_FAILED: Indicates that the VPC endpoint creation failed.</li>
/// <li>ACTIVE: Indicates that the VPC endpoint is currently active.</li>
/// <li>UPDATING: Indicates that the VPC endpoint is currently being updated.</li>
/// <li>UPDATE_FAILED: Indicates that the VPC endpoint update failed.</li>
/// <li>DELETING: Indicates that the VPC endpoint is currently being deleted.</li>
/// <li>DELETE_FAILED: Indicates that the VPC endpoint deletion failed.</li>
/// </ul>
/// </p>
#[non_exhaustive]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum VpcEndpointStatus {
    #[allow(missing_docs)] // documentation missing in model
    Active,
    #[allow(missing_docs)] // documentation missing in model
    CreateFailed,
    #[allow(missing_docs)] // documentation missing in model
    Creating,
    #[allow(missing_docs)] // documentation missing in model
    DeleteFailed,
    #[allow(missing_docs)] // documentation missing in model
    Deleting,
    #[allow(missing_docs)] // documentation missing in model
    UpdateFailed,
    #[allow(missing_docs)] // documentation missing in model
    Updating,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for VpcEndpointStatus {
    fn from(s: &str) -> Self {
        match s {
            "ACTIVE" => VpcEndpointStatus::Active,
            "CREATE_FAILED" => VpcEndpointStatus::CreateFailed,
            "CREATING" => VpcEndpointStatus::Creating,
            "DELETE_FAILED" => VpcEndpointStatus::DeleteFailed,
            "DELETING" => VpcEndpointStatus::Deleting,
            "UPDATE_FAILED" => VpcEndpointStatus::UpdateFailed,
            "UPDATING" => VpcEndpointStatus::Updating,
            other => VpcEndpointStatus::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for VpcEndpointStatus {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(VpcEndpointStatus::from(s))
    }
}
impl VpcEndpointStatus {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            VpcEndpointStatus::Active => "ACTIVE",
            VpcEndpointStatus::CreateFailed => "CREATE_FAILED",
            VpcEndpointStatus::Creating => "CREATING",
            VpcEndpointStatus::DeleteFailed => "DELETE_FAILED",
            VpcEndpointStatus::Deleting => "DELETING",
            VpcEndpointStatus::UpdateFailed => "UPDATE_FAILED",
            VpcEndpointStatus::Updating => "UPDATING",
            VpcEndpointStatus::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ACTIVE",
            "CREATE_FAILED",
            "CREATING",
            "DELETE_FAILED",
            "DELETING",
            "UPDATE_FAILED",
            "UPDATING",
        ]
    }
}
impl ::std::convert::AsRef<str> for VpcEndpointStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl VpcEndpointStatus {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}