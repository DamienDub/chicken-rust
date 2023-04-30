use yew::prelude::*;

use crate::utils::transformer::*;

use gloo_console::log;

#[function_component(Test)]
pub fn test() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        
        let key_128 = "00112233445566778899AABBCCDDEEFF";
        let key_192 = "00112233445566778899AABBCCDDEEFF0011223344556677";
        let key_256 = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
        let iv = "00000000000000000000000000000000";


        // Base 64 encoding
        // echo -n "Hey Doc" | openssl enc -base64
        assert_eq!(base64_encode("Hey Doc"), "SGV5IERvYw==");

        // Base 64 decoding
        // echo "SGV5IERvYw==" | openssl enc -base64 -d
        assert_eq!(base64_decode("SGV5IERvYw=="), "Hey Doc");

        // ---------------------------------------------------------------------------------------------

        // URL encoding
        assert_eq!(url_encode("http://url.com/a b c"), "http%3A%2F%2Furl.com%2Fa%20b%20c");

        // URL encoding
        assert_eq!(url_decode("http%3A%2F%2Furl.com%2Fa%20b%20c"), "http://url.com/a b c");

        // ---------------------------------------------------------------------------------------------

        // SHA-1
        // echo -n "Hey Doc" | openssl sha1
        assert_eq!(sha1_hash("Hey Doc"), "fee2f86cd7b7db93676e1aa4b44acea8fbc4b6f0");

        // SHA-256
        // echo -n "Hey Doc" | openssl sha256
        assert_eq!(sha256_hash("Hey Doc"), "eacbbed709035947930fd4207a7fd316a18be19bdb6308ab882270cd6dcc9db5");

        // ---------------------------------------------------------------------------------------------

        // AES CBC 128 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-128-cbc --base64 -K '00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(aes_cbc_encrypt(128, key_128, iv, "Hey Doc", false), "iYb0EyQStjUulA4sfAA4jw==");

        // AES CBC 128 decryption
        // echo 'iYb0EyQStjUulA4sfAA4jw==' | openssl enc -d -aes-128-cbc --base64 -K '00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(aes_cbc_decrypt(128, key_128, iv, "iYb0EyQStjUulA4sfAA4jw==", false), "Hey Doc");

        // AES CBC 196 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-192-cbc --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677' -iv '00000000000000000000000000000000'
        assert_eq!(aes_cbc_encrypt(192, key_192, iv, "Hey Doc", false), "3wviCl5mie4Ub4sS7X7STw==");

        // AES CBC 192 decryption
        // echo '3wviCl5mie4Ub4sS7X7STw==' | openssl enc -d -aes-192-cbc --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677' -iv '00000000000000000000000000000000'
        assert_eq!(aes_cbc_decrypt(192, key_192, iv, "3wviCl5mie4Ub4sS7X7STw==", false), "Hey Doc");

        // AES CBC 256 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-256-cbc --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(aes_cbc_encrypt(256, key_256, iv, "Hey Doc", false), "1wI8/eKQIzIRSdm+eSx4kw==");

        // AES CBC 256 decryption
        // echo '1wI8/eKQIzIRSdm+eSx4kw==' | openssl enc -d -aes-256-cbc --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(aes_cbc_decrypt(256, key_256, iv, "1wI8/eKQIzIRSdm+eSx4kw==", false), "Hey Doc");

        // ---------------------------------------------------------------------------------------------

        // AES ECB 128 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-128-ecb --base64 -K '00112233445566778899AABBCCDDEEFF'
        assert_eq!(aes_ecb_encrypt(128, key_128, "Hey Doc", false), "iYb0EyQStjUulA4sfAA4jw==");

        // AES ECB 128 decryption
        // echo 'iYb0EyQStjUulA4sfAA4jw==' | openssl enc -d -aes-128-ecb --base64 -K '00112233445566778899AABBCCDDEEFF'
        assert_eq!(aes_ecb_decrypt(128, key_128, "iYb0EyQStjUulA4sfAA4jw==", false), "Hey Doc");

        // AES ECB 192 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-192-ecb --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677'
        assert_eq!(aes_ecb_encrypt(192, key_192, "Hey Doc", false), "3wviCl5mie4Ub4sS7X7STw==");

        // AES ECB 128 decryption
        // echo '3wviCl5mie4Ub4sS7X7STw==' | openssl enc -d -aes-192-ecb --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677'
        assert_eq!(aes_ecb_decrypt(192, key_192, "3wviCl5mie4Ub4sS7X7STw==", false), "Hey Doc");

        // AES ECB 256 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-256-ecb --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
        assert_eq!(aes_ecb_encrypt(256, key_256, "Hey Doc", false), "1wI8/eKQIzIRSdm+eSx4kw==");

        // AES ECB 128 decryption
        // echo '1wI8/eKQIzIRSdm+eSx4kw==' | openssl enc -d -aes-256-ecb --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
        assert_eq!(aes_ecb_decrypt(256, key_256, "1wI8/eKQIzIRSdm+eSx4kw==", false), "Hey Doc");

        log!("All good");
    });

    html! {
        <main>
        <div>

            <div>
                 <button onclick={onclick}>{ "Launch tests" }</button>
            </div>

        </div>
        </main>
    }
}
