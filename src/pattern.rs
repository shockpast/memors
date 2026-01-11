#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default, Clone)]
pub struct Signature {
    pub bytes: Vec<u8>,
    pub mask: Vec<bool>
}

/// Creates a Signature from "FF ?? FF 0A CC 0A 0A 0A CC"-alike pattern
pub fn ida(sig: &str) -> Signature {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    let tokens = sig.split_whitespace();

    for tok in tokens {
        if tok.contains('?') {
            bytes.push(0);
            mask.push(false);
        } else {
            bytes.push(u8::from_str_radix(tok, 16).unwrap());
            mask.push(true);
        }
    }

    Signature { bytes, mask }
}

/// Creates a Signature from "\x03\x00\xFF\x0A"-alike pattern
pub fn code(sig: &str) -> Signature {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    let tokens = sig.split("\\x").skip(1);

    for tok in tokens {
        if tok == "00" {
            bytes.push(0);
            mask.push(false);
        } else {
            bytes.push(u8::from_str_radix(tok, 16).unwrap_or_default());
            mask.push(true);
        }
    }

    Signature { bytes, mask }
}