//! Certificate policy.

use core::iter::Iterator;

use crate::{Cert, Error, der, verify_cert::VerifiedPath};

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
    }
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
    pub(crate) fn with_qualifiers(
        &self,
        qualifiers: Option<&untrusted::Input<'a>>,
    ) -> Self {
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
            Self::Any { qualifiers, .. } |
            Self::Specific { qualifiers, .. } => qualifiers.as_ref(),
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
            (Any, Specific(oid)) | (Specific(oid), Any) =>
                oid.as_slice_less_safe() == ANY_POLICY_OID,
            (Specific(oid1), Specific(oid2)) =>
                oid1.as_slice_less_safe() == oid2.as_slice_less_safe(),
        }
    }
}

impl<'a> core::fmt::Display for PolicyOidRef<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PolicyOidRef::*;
        write!(f, "PolicyOID({:?})", match self {
            Any => ANY_POLICY_OID,
            Specific(oid) => oid.as_slice_less_safe(),
        })
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
        let policy =
            der::expect_tag(&mut self.reader, der::Tag::Sequence)
                .and_then(|policy| {
                    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
                    policy.read_all(Error::BadDer, |policy| {
                        // must start with the policy ID
                        let oid = der::expect_tag(policy, der::Tag::OID)?;
                        // optional qualifiers may follow
                        let qualifiers = if policy.at_end() {
                            None
                        } else {
                            Some(der::expect_tag(policy, der::Tag::Sequence)?)
                        };
                        if oid.as_slice_less_safe() == ANY_POLICY_OID {
                            Ok(CertificatePolicy::Any { qualifiers })
                        } else {
                            Ok(CertificatePolicy::Specific { oid, qualifiers })
                        }
                    })
                });
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

/// Checks the policy tree.
///
/// Simplified and reversed implementation of certificate policies validation
/// described in RFC 5280 section 6.1
/// https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
///
/// RFC 5280 section 6.1.2 starts from "any policy", though, this function
/// starts from each policy ID in `user_initial_policy_set` because this
/// function focuses only on verifying if any of acceptable policies is in the
/// valid policy tree.
#[allow(unreachable_pub, unused)]
pub fn check_policy_tree(
    path: &VerifiedPath<'_>,
    user_initial_policy_set: &[&[u8]],
) -> Result<(), String> {
    let cert_chain = CertificateChain::new(path);
    for policy_id in user_initial_policy_set {
        match check_policy_tree_inner(
            cert_chain.iter(),
            CertificatePolicy::from_oid(*policy_id),
        ) {
            Ok(valid) => {
                if valid {
                    return Ok(());
                }
            }
            Err(e) => return Err(e),
        };
    }
    // no acceptable policy was included in the valid policy tree
    Err("no acceptable policy was included".to_string())
}

fn check_policy_tree_inner<'a>(
    mut cert_chain: impl Iterator<Item = &'a Cert<'a>> + Clone,
    expected_policy: CertificatePolicy,
) -> Result<bool, String> {
    // verified if the certificate chain ends
    let cert = cert_chain.next();
    if cert.is_none() {
        return Ok(true);
    }
    let cert = cert.unwrap();
    // checks the policies
    match cert.certificate_policies {
        Some(policies) => {
            // processes policies
            let mut any_policy: Option<CertificatePolicy> = None;
            for policy in read_certificate_policies(policies) {
                let policy = policy.map_err(|e| e.to_string())?;
                if policy.is_any() {
                    // processing of any policy is the last resort
                    // RFC 5280 section 6.1.3 (d) (2)
                    if any_policy.is_some() {
                        // duplicate any policies
                        return Err("duplicate any policies".to_string());
                    }
                    any_policy.replace(policy);
                } else {
                    // RFC 5280 section 6.1.3 (d) (1) (i) || (ii)
                    if expected_policy.oid() == policy.oid() || expected_policy.is_any() {
                        let valid = check_policy_tree_inner(cert_chain.clone(), policy)?;
                        if valid {
                            return Ok(true);
                        }
                    }
                }
            }
            match any_policy {
                Some(any_policy) => {
                    // RFC 5280 section 6.1.3 (d) (2)
                    check_policy_tree_inner(
                        cert_chain,
                        expected_policy.with_qualifiers(any_policy.qualifiers()),
                    )
                }
                None => Ok(false),
            }
        }
        None => {
            // treats as "any policy"
            // TODO: unnacceptable in some conditions
            // - inhibited any policy
            // - positive explicit policy
            check_policy_tree_inner(cert_chain, CertificatePolicy::any())
        }
    }
}

const MAX_SUB_CA_COUNT: usize = 6; // taken from verify_cert.rs

// This struct is introduced to reverse the order of intermediate certificates.
// Because the intermediate certificates in `VerifiedPath` is ordered from the
// end entity towards the root certificate while the algorithm described in RFC
// 5280 processes certificates from the root certificate towards the end entity.
struct CertificateChain<'a> {
    certificates: [Option<&'a Cert<'a>>; MAX_SUB_CA_COUNT + 1],
    len: usize,
}

impl<'a> CertificateChain<'a> {
    fn new(path: &'a VerifiedPath<'a>) -> Self {
        let mut certificates: [Option<&'a Cert<'a>>; MAX_SUB_CA_COUNT + 1] =
            [None; MAX_SUB_CA_COUNT + 1];
        let mut len = 0;
        certificates[0] = Some(&*path.end_entity());
        len += 1;
        for cert in path.intermediate_certificates() {
            assert!(len <= MAX_SUB_CA_COUNT);
            certificates[len] = Some(cert);
            len += 1;
        }
        Self { certificates, len }
    }

    fn iter<'b>(&'b self) -> CertificateIterator<'a, 'b> {
        CertificateIterator {
            certificates: &self.certificates[..self.len],
        }
    }
}

#[derive(Clone)]
struct CertificateIterator<'a, 'b> {
    certificates: &'b [Option<&'a Cert<'a>>],
}

impl<'a, 'b> Iterator for CertificateIterator<'a, 'b> {
    type Item = &'a Cert<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((tail, heads)) = self.certificates.split_last() {
            self.certificates = heads;
            Some(tail.unwrap())
        } else {
            None
        }
    }
}
