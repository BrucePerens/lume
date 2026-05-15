use mailparse::*;
use crate::LumeError;

pub struct ParsedMail {
    pub compressible_text: Vec<u8>,
    pub binary_attachments: Vec<Vec<u8>>,
}

impl crate::LumeEngine {
    pub fn parse_and_split(&self, raw_mail: &[u8]) -> Result<ParsedMail, LumeError> {
        let parsed = parse_mail(raw_mail)
            .map_err(|e| LumeError::Mime(e.to_string()))?;
        
        let mut text_parts = Vec::new();
        let mut binary_parts = Vec::new();

        for subpart in parsed.subparts.iter() {
            let ctype = subpart.ctype.mimetype.clone();
            
            // If it's text, HTML, or routing headers, route to compressor
            if ctype.starts_with("text/") || ctype == "message/rfc822" {
                text_parts.extend_from_slice(subpart.get_body_raw().map_err(|e| LumeError::Mime(e.to_string()))?.as_slice());
            } else {
                // If it's an image, zip, or application data, keep it raw
                binary_parts.push(subpart.get_body_raw().map_err(|e| LumeError::Mime(e.to_string()))?);
            }
        }

        Ok(ParsedMail {
            compressible_text: text_parts,
            binary_attachments: binary_parts,
        })
    }
}
