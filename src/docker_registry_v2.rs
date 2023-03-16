use std::{
    fmt::{Display, Write},
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImageQualifierParseError {
    #[error("FLORP")]
    MissingRepositoryName,
    #[error("FLORP")]
    InvalidCharacterInDomain,
    #[error("FLORP")]
    InvalidPort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDomain {
    pub hostname: String,
    pub port: Option<u16>,
}

impl Display for ParsedDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hostname)?;
        if let Some(port) = self.port {
            f.write_char(':')?;
            port.fmt(f)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub tag: String,
    pub digest: Option<String>,
}

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.tag)?;
        if let Some(digest) = &self.digest {
            f.write_char('@')?;
            f.write_str(digest)?;
        }
        Ok(())
    }
}

/// An image reference in a registry, parsed according to the grammer specified [here][1].
///
/// Not all fields are mandatory.
///
/// Parsing is permissive and might not return an error for slightly invalid input.
/// This behaviour might change in the future to conform with grammer and reject more invalid inputs.
///
/// # Example
/// ```
/// let a: ParsedImageReference = "ubuntu".parse().unwrap();
/// assert_eq!(a, ParsedImageReference {
///     registry: None,
///     repository: "ubuntu".into(),
///     tag: None,
/// });
/// ```
///
/// [1]: https://github.com/containers/image/blob/7900588000bd2ef355b3c966949c6139806b2dad/docker/reference/reference.go#L4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedImageReference {
    pub registry: Option<ParsedDomain>,
    pub repository: String,
    pub tag: Option<Tag>,
}

impl Display for ParsedImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(registry) = &self.registry {
            registry.fmt(f)?;
            f.write_char('/')?;
        }

        f.write_str(&self.repository)?;

        if let Some(tag) = &self.tag {
            f.write_char(':')?;
            tag.fmt(f)?;
        }

        Ok(())
    }
}

fn split_zero_or_once(haystack: &str, needle: char) -> (&str, Option<&str>) {
    match haystack.split_once(needle) {
        None => (haystack, None),
        Some((head, tail)) => (head, Some(tail)),
    }
}

fn parse_registry(registry: &str) -> Result<ParsedDomain, ImageQualifierParseError> {
    let mut registry_components = registry.splitn(2, ':');
    // PANIC: Split always returns at least one item, even if there's no separator.
    let hostname = registry_components
        .next()
        .expect("I have greatly misjudged the situation");
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ['.', '-'].contains(&c))
    {
        return Err(ImageQualifierParseError::InvalidCharacterInDomain);
    }
    let port = match registry_components.next() {
        None => None,
        Some(port) => Some(
            port.parse::<u16>()
                .map_err(|_| ImageQualifierParseError::InvalidPort)?,
        ),
    };
    Ok(ParsedDomain {
        hostname: hostname.to_owned(),
        port,
    })
}

impl FromStr for ParsedImageReference {
    type Err = ImageQualifierParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (registry, repository) = match split_zero_or_once(s, '/') {
            (repository, None) => (None, repository),
            (registry, Some(repository)) => (Some(parse_registry(registry)?), repository),
        };

        let (repository, tag) = split_zero_or_once(repository, ':');

        let tag = tag.map(|repository_tag| {
            let (tag, digest) = split_zero_or_once(repository_tag, '@');
            Tag {
                tag: tag.to_owned(),
                digest: digest.map(ToOwned::to_owned),
            }
        });

        Ok(ParsedImageReference {
            registry,
            repository: repository.to_owned(),
            tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsed_reference() {
        let test_vectors = [
            ("ubuntu", ParsedImageReference {
                registry: None,
                repository: "ubuntu".into(),
                tag: None,
            }),

            ("registry.example.com/ubuntu", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "registry.example.com".into(), port: None }),
                repository: "ubuntu".into(),
                tag: None,
            }),

            ("registry.example.com:8000/ubuntu", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "registry.example.com".into(), port: Some(8000) }),
                repository: "ubuntu".into(),
                tag: None,
            }),

            ("registry.example.com:8000/image/name", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "registry.example.com".into(), port: Some(8000) }),
                repository: "image/name".into(),
                tag: None,
            }),

            ("staging-registry.example.com:8000/image/name", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "staging-registry.example.com".into(), port: Some(8000) }),
                repository: "image/name".into(),
                tag: None,
            }),

            ("example.com/image:some_tag", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "example.com".into(), port: None }),
                repository: "image".into(),
                tag: Some(Tag { tag: "some_tag".into(), digest: None }),
            }),

            ("example.com:8000/image:some_tag", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "example.com".into(), port: Some(8000) }),
                repository: "image".into(),
                tag: Some(Tag { tag: "some_tag".into(), digest: None }),
            }),

            ("example.com:8000/image:some_tag@55c442300ad577bd85d7158e6e29c8c9bb55a91fe4873693587cd078d39fd2c1", ParsedImageReference {
                registry: Some(ParsedDomain { hostname: "example.com".into(), port: Some(8000) }),
                repository: "image".into(),
                tag: Some(Tag { tag: "some_tag".into(), digest: Some("55c442300ad577bd85d7158e6e29c8c9bb55a91fe4873693587cd078d39fd2c1".into()) }),
            }),
        ];

        for (src, parsed) in test_vectors.into_iter() {
            assert_eq!(parsed.to_string(), src);
            assert_eq!(src.parse(), Ok(parsed));
        }
    }
}
