use rand::Rng;

pub fn random_string_generate(
    length: usize,
    with_lowercase: bool,
    with_uppercase: bool,
    with_numbers: bool,
) -> Result<String, &'static str> {
    if !with_lowercase && !with_uppercase && !with_numbers {
        return Err("You must choose something");
    }

    let mut charset: Vec<u8> = Vec::new();
    if with_lowercase {
        charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    if with_uppercase {
        charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if with_numbers {
        charset.extend_from_slice(b"0123456789");
    }

    let mut rng = rand::thread_rng();
    Ok((0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect())
}
