use askama::Template;
use email_address::EmailAddress;
use crate::config::EmailAuthProviderConfig;

#[derive(Template)]
#[template(path = "register_email.html")]
pub struct RegisterEmail<'a> {
    pub register_link: &'a str,
}

fn domain_defender(email_address: &str, config: &EmailAuthProviderConfig) -> bool {
    if !EmailAddress::is_valid(email_address) {
        return false;
    }
    let domain = email_address.split('@').last();
    if domain.is_none() {
        return false;
    }
    let domain = domain.unwrap();
    if config.enable_domain_whitelist {
        return config.domain_whitelist.contains(&domain.to_string());
    }
    if config.enable_domain_blacklist {
        return !config.domain_blacklist.contains(&domain.to_string());
    }
    true
}

#[cfg(test)]
mod test {
    use askama::Template;
    #[test]
    fn test_register_email() {
        let register_email = super::RegisterEmail {
            register_link: "https://example.com/register",
        };
        register_email.render().unwrap();
    }
    #[test]
    fn test_defender_whitelist() {
        let config = crate::config::EmailAuthProviderConfig {
            verify_link_base: "https://example.com/verify".to_string(),
            enable_domain_whitelist: true,
            domain_whitelist: vec!["example.com".to_string(), "example.org".to_string()],
            enable_domain_blacklist: false,
            domain_blacklist: vec![],
        };
        assert!(!super::domain_defender("a@b.com", &config));
        assert!(!super::domain_defender("invalid", &config));
        assert!(super::domain_defender("1234@example.com", &config));
        assert!(super::domain_defender("2345@example.org", &config));
    }
    #[test]
    fn test_defender_blacklist() {
        let config = crate::config::EmailAuthProviderConfig {
            verify_link_base: "https://example.com/verify".to_string(),
            enable_domain_whitelist: false,
            domain_whitelist: vec![],
            enable_domain_blacklist: true,
            domain_blacklist: vec!["example.com".to_string(), "example.org".to_string()],
        };
        assert!(super::domain_defender("123@abc.com", &config));
        assert!(!super::domain_defender("invalid", &config));
        assert!(!super::domain_defender("a@example.com", &config));
    }
}