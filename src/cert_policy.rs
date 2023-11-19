//! Certificate policy.

use core::iter::Iterator;

use crate::{der, Error};

// OID for any policy.
const ANY_POLICY_OID: &[u8] = &oid![2u8, 5u8, 29u8, 32u8, 0u8];

/// Certificate policy.
#[derive(Clone, Debug)]
pub(crate) enum CertificatePolicy<'a> {
    /// Any policy.
    Any {
        qualifiers: Option<untrusted::Input<'a>>,
    },
    /// Specific policy.
    Specific {
        oid: untrusted::Input<'a>,
        qualifiers: Option<untrusted::Input<'a>>,
    },
}

impl<'a> CertificatePolicy<'a> {
    /// Creates an any policy without qualifiers.
    pub(crate) fn any() -> Self {
        Self::Any { qualifiers: None }
    }

    /// Creates a policy from a given policy ID (OID) without qualifiers.
    ///
    /// Returns [`CertificatePolicy::Any`] if `oid` represents "any policy",
    /// otherwise [`CertificatePolicy::Specific`].
    pub(crate) fn from_oid(oid: impl Into<untrusted::Input<'a>>) -> Self {
        let oid = oid.into();
        if oid.as_slice_less_safe() == ANY_POLICY_OID {
            Self::Any { qualifiers: None }
        } else {
            Self::Specific {
                oid: oid.into(),
                qualifiers: None,
            }
        }
    }

    /// Creates a policy whose qualifiers are replaced with the given ones.
    pub(crate) fn with_qualifiers(&self, qualifiers: Option<&untrusted::Input<'a>>) -> Self {
        match self {
            Self::Any { .. } => Self::Any {
                qualifiers: qualifiers.cloned(),
            },
            Self::Specific { oid, .. } => Self::Specific {
                oid: oid.clone(),
                qualifiers: qualifiers.cloned(),
            },
        }
    }

    /// Returns if the policy is "any policy".
    pub(crate) fn is_any(&self) -> bool {
        match self {
            Self::Any { .. } => true,
            Self::Specific { .. } => false,
        }
    }

    /// Returns the policy identifier (OID).
    pub(crate) fn oid(&self) -> PolicyOidRef<'a> {
        match self {
            Self::Any { .. } => PolicyOidRef::Any,
            Self::Specific { oid, .. } => PolicyOidRef::Specific(*oid),
        }
    }

    /// Returns the policy qualifiers.
    pub(crate) fn qualifiers(&self) -> Option<&untrusted::Input<'a>> {
        match self {
            Self::Any { qualifiers, .. } | Self::Specific { qualifiers, .. } => qualifiers.as_ref(),
        }
    }
}

impl<'a> core::fmt::Display for CertificatePolicy<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use CertificatePolicy::*;
        match self {
            Any { qualifiers } => write!(
                f,
                "Any(qualifier={:?})",
                qualifiers.map(|q| q.as_slice_less_safe()),
            ),
            Specific { oid, qualifiers } => write!(
                f,
                "Specific(oid={:?}, qualifiers={:?})",
                oid.as_slice_less_safe(),
                qualifiers.map(|q| q.as_slice_less_safe()),
            ),
        }
    }
}

/// Referencde to a policy identificer (OID).
#[derive(Clone, Debug)]
pub(crate) enum PolicyOidRef<'a> {
    /// Any policy.
    Any,
    /// Speicific policy.
    Specific(untrusted::Input<'a>),
}

impl<'a> PartialEq<PolicyOidRef<'_>> for PolicyOidRef<'a> {
    fn eq(&self, other: &PolicyOidRef<'_>) -> bool {
        use PolicyOidRef::*;
        match (self, other) {
            (Any, Any) => true,
            (Any, Specific(oid)) | (Specific(oid), Any) => {
                oid.as_slice_less_safe() == ANY_POLICY_OID
            }
            (Specific(oid1), Specific(oid2)) => {
                oid1.as_slice_less_safe() == oid2.as_slice_less_safe()
            }
        }
    }
}

impl<'a> core::fmt::Display for PolicyOidRef<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PolicyOidRef::*;
        write!(
            f,
            "PolicyOID({:?})",
            match self {
                Any => ANY_POLICY_OID,
                Specific(oid) => oid.as_slice_less_safe(),
            }
        )
    }
}

/// Reads policy from a given input.
pub(crate) fn read_certificate_policies<'a>(
    input: untrusted::Input<'a>,
) -> ReadCertificatePolicies<'a> {
    ReadCertificatePolicies {
        reader: untrusted::Reader::new(input),
    }
}

/// Reader of certificate policies.
pub(crate) struct ReadCertificatePolicies<'a> {
    reader: untrusted::Reader<'a>,
}

impl<'a> Iterator for ReadCertificatePolicies<'a> {
    type Item = Result<CertificatePolicy<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }
        let policy = der::expect_tag_and_get_value(&mut self.reader, der::Tag::Sequence).and_then(
            |policy| {
                // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
                policy.read_all(Error::BadDer, |policy| {
                    // must start with the policy ID
                    let oid = der::expect_tag_and_get_value(policy, der::Tag::OID)?;
                    // optional qualifiers may follow
                    let qualifiers = if policy.at_end() {
                        None
                    } else {
                        Some(der::expect_tag_and_get_value(policy, der::Tag::Sequence)?)
                    };
                    if oid.as_slice_less_safe() == ANY_POLICY_OID {
                        Ok(CertificatePolicy::Any { qualifiers })
                    } else {
                        Ok(CertificatePolicy::Specific { oid, qualifiers })
                    }
                })
            },
        );
        Some(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_policy_any_should_be_created_from_any_policy_oid() {
        assert!(matches!(
            CertificatePolicy::from_oid(ANY_POLICY_OID),
            CertificatePolicy::Any { qualifiers: None },
        ));
    }

    #[test]
    fn certificate_policy_specific_should_be_created_from_specific_oid() {
        let oid_in: &[u8] = &oid![2, 5, 29, 15];
        assert!(matches!(
            CertificatePolicy::from_oid(oid_in),
            CertificatePolicy::Specific {
                oid,
                qualifiers: None
            } if oid.as_slice_less_safe() == oid_in,
        ));
    }

    #[test]
    fn any_policy_oid_ref_should_equal_any_policy_oid() {
        assert_eq!(PolicyOidRef::Any, PolicyOidRef::Any);
    }

    #[test]
    fn any_policy_oid_ref_should_not_equal_specific_policy_oid_ref() {
        assert_ne!(
            PolicyOidRef::Any,
            PolicyOidRef::Specific(untrusted::Input::from(&oid![2, 5, 29, 15])),
        );
    }

    #[test]
    fn any_policy_oid_ref_should_equal_specific_policy_oid_ref_referencing_any_policy() {
        assert_eq!(
            PolicyOidRef::Any,
            PolicyOidRef::Specific(untrusted::Input::from(&ANY_POLICY_OID)),
        );
    }

    #[test]
    fn specific_policy_oid_ref_should_equal_same_specific_policy_oid_ref() {
        assert_eq!(
            PolicyOidRef::Specific(untrusted::Input::from(&oid![2, 5, 29, 15])),
            PolicyOidRef::Specific(untrusted::Input::from(&oid![2, 5, 29, 15])),
        );
    }

    #[test]
    fn specific_policy_oid_ref_should_not_equal_different_specific_policy_oid_ref() {
        assert_ne!(
            PolicyOidRef::Specific(untrusted::Input::from(&oid![2, 5, 29, 15])),
            PolicyOidRef::Specific(untrusted::Input::from(&oid![2, 5, 29, 32])),
        );
    }
}
