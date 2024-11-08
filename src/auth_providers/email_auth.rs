use askama::Template;

#[derive(Template)]
#[template(path = "register_email.html")]
pub struct RegisterEmail<'a> {
    pub register_link: &'a str,
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
}