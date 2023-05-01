use rand::Rng;


pub fn random_string_generate(
    length: usize,
    with_lowercase: bool,
    with_uppercase: bool,
    with_numbers: bool,
) -> String {
    if !with_lowercase && !with_uppercase && !with_numbers {
        return "You must choose something".to_string();
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
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

