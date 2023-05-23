use yew::prelude::*;

use crate::utils::coder::*;
use crate::utils::crypter::*;
use crate::utils::hasher::*;

use gloo_console::log;

#[function_component(Test)]
pub fn test() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let key_64 = "0011223344556677";
        let key_128 = "00112233445566778899AABBCCDDEEFF";
        let key_192 = "00112233445566778899AABBCCDDEEFF0011223344556677";
        let key_256 = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
        let iv_64 = "0000000000000000";
        let iv_128 = "00000000000000000000000000000000";

        // Base 64 encoding
        // echo -n "Hey Doc" | openssl enc -base64
        assert_eq!(base64_encode("Hey Doc"), "SGV5IERvYw==");

        // Base 64 decoding
        // echo "SGV5IERvYw==" | openssl enc -base64 -d
        assert_eq!(base64_decode("SGV5IERvYw==").unwrap(), "Hey Doc");

        // ---------------------------------------------------------------------------------------------

        // URL encoding
        assert_eq!(
            url_encode("http://url.com/a b c"),
            "http%3A%2F%2Furl.com%2Fa%20b%20c"
        );

        // URL encoding
        assert_eq!(
            url_decode("http%3A%2F%2Furl.com%2Fa%20b%20c").unwrap(),
            "http://url.com/a b c"
        );

        // ---------------------------------------------------------------------------------------------

        // MD5
        // echo -n "Hey Doc" | openssl md5
        assert_eq!(md5_hash("Hey Doc"), "8fe916535abcbd8fafc80bc25b2da127");

        // SHA-1
        // echo -n "Hey Doc" | openssl sha1
        assert_eq!(
            sha1_hash("Hey Doc"),
            "fee2f86cd7b7db93676e1aa4b44acea8fbc4b6f0"
        );

        // SHA-256
        // echo -n "Hey Doc" | openssl sha256
        assert_eq!(
            sha256_hash("Hey Doc"),
            "eacbbed709035947930fd4207a7fd316a18be19bdb6308ab882270cd6dcc9db5"
        );

        // ---------------------------------------------------------------------------------------------

        // DES CBC - Encryption
        // echo -n 'Hey Doc' | openssl enc -des-cbc --base64 -K '0011223344556677' -iv '0000000000000000' -provider legacy
        assert_eq!(
            des_cbc_encrypt(key_64, iv_64, "Hey Doc", false).unwrap(),
            "hdvpB45DUEI="
        );

        // DES CBC - Decryption
        // echo 'hdvpB45DUEI=' | openssl enc -d -des-cbc --base64 -K '0011223344556677' -iv '0000000000000000' -provider legacy
        assert_eq!(
            des_cbc_decrypt(key_64, iv_64, "hdvpB45DUEI=", false).unwrap(),
            "Hey Doc"
        );

        // ---------------------------------------------------------------------------------------------

        // DES ECB - Encryption
        // echo -n 'Hey Doc' | openssl enc -des-ecb --base64 -K '0011223344556677' -provider legacy
        assert_eq!(
            des_ecb_encrypt(key_64, "Hey Doc", false).unwrap(),
            "hdvpB45DUEI="
        );

        // DES ECB - Decryption
        // echo 'hdvpB45DUEI=' | openssl enc -d -des-ecb --base64 -K '0011223344556677' -provider legacy
        assert_eq!(
            des_ecb_decrypt(key_64, "hdvpB45DUEI=", false).unwrap(),
            "Hey Doc"
        );

        // ---------------------------------------------------------------------------------------------

        // 3DES CBC - Keying option 2 - Encryption
        // echo -n 'Hey Doc' | openssl enc -des-ede-cbc --base64 -K '00112233445566778899AABBCCDDEEFF' -iv '0000000000000000'
        assert_eq!(
            tripledes_keying2_cbc_encrypt(key_128, iv_64, "Hey Doc", false).unwrap(),
            "wz6+e1DYKrA="
        );

        // 3DES CBC - Keying option 2 - Decryption
        // echo 'wz6+e1DYKrA=' | openssl enc -d -des-ede-cbc --base64 -K '00112233445566778899AABBCCDDEEFF' -iv '0000000000000000'
        assert_eq!(
            tripledes_keying2_cbc_decrypt(key_128, iv_64, "wz6+e1DYKrA=", false).unwrap(),
            "Hey Doc"
        );

        // 3DES CBC - Keying option 3 - Encryption
        // echo -n 'Hey Doc' | openssl enc -des-ede3-cbc --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677' -iv '0000000000000000'
        assert_eq!(
            tripledes_keying3_cbc_encrypt(key_192, iv_64, "Hey Doc", false).unwrap(),
            "wz6+e1DYKrA="
        );

        // 3DES CBC - Keying option 3 - Decryption
        // echo 'wz6+e1DYKrA=' | openssl enc -d -des-ede3-cbc --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677' -iv '0000000000000000'
        assert_eq!(
            tripledes_keying3_cbc_decrypt(key_192, iv_64, "wz6+e1DYKrA=", false).unwrap(),
            "Hey Doc"
        );

        // ---------------------------------------------------------------------------------------------

        // 3DES ECB - Keying option 2 - Encryption
        // echo -n 'Hey Doc' | openssl enc -des-ede-ecb --base64 -K '00112233445566778899AABBCCDDEEFF'
        assert_eq!(
            tripledes_keying2_ecb_encrypt(key_128, "Hey Doc", false).unwrap(),
            "wz6+e1DYKrA="
        );

        // 3DES ECB - Keying option 2 - Decryption
        // echo 'wz6+e1DYKrA=' | openssl enc -d -des-ede-ecb --base64 -K '00112233445566778899AABBCCDDEEFF'
        assert_eq!(
            tripledes_keying2_ecb_decrypt(key_128, "wz6+e1DYKrA=", false).unwrap(),
            "Hey Doc"
        );

        // 3DES ECB - Keying option 3 - Encryption
        // echo -n 'Hey Doc' | openssl enc -des-ede3-ecb --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677'
        assert_eq!(
            tripledes_keying3_ecb_encrypt(key_192, "Hey Doc", false).unwrap(),
            "wz6+e1DYKrA="
        );

        // 3DES ECB - Keying option 3 - Decryption
        // echo 'wz6+e1DYKrA=' | openssl enc -d -des-ede3-ecb --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677'
        assert_eq!(
            tripledes_keying3_ecb_decrypt(key_192, "wz6+e1DYKrA=", false).unwrap(),
            "Hey Doc"
        );

        // ---------------------------------------------------------------------------------------------

        // AES CBC 128 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-128-cbc --base64 -K '00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(
            aes_128_cbc_encrypt(key_128, iv_128, "Hey Doc", false).unwrap(),
            "iYb0EyQStjUulA4sfAA4jw=="
        );

        // AES CBC 128 decryption
        // echo 'iYb0EyQStjUulA4sfAA4jw==' | openssl enc -d -aes-128-cbc --base64 -K '00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(
            aes_128_cbc_decrypt(key_128, iv_128, "iYb0EyQStjUulA4sfAA4jw==", false).unwrap(),
            "Hey Doc"
        );

        // AES CBC 196 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-192-cbc --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677' -iv '00000000000000000000000000000000'
        assert_eq!(
            aes_192_cbc_encrypt(key_192, iv_128, "Hey Doc", false).unwrap(),
            "3wviCl5mie4Ub4sS7X7STw=="
        );

        // AES CBC 192 decryption
        // echo '3wviCl5mie4Ub4sS7X7STw==' | openssl enc -d -aes-192-cbc --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677' -iv '00000000000000000000000000000000'
        assert_eq!(
            aes_192_cbc_decrypt(key_192, iv_128, "3wviCl5mie4Ub4sS7X7STw==", false).unwrap(),
            "Hey Doc"
        );

        // AES CBC 256 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-256-cbc --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(
            aes_256_cbc_encrypt(key_256, iv_128, "Hey Doc", false).unwrap(),
            "1wI8/eKQIzIRSdm+eSx4kw=="
        );

        // AES CBC 256 decryption
        // echo '1wI8/eKQIzIRSdm+eSx4kw==' | openssl enc -d -aes-256-cbc --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' -iv '00000000000000000000000000000000'
        assert_eq!(
            aes_256_cbc_decrypt(key_256, iv_128, "1wI8/eKQIzIRSdm+eSx4kw==", false).unwrap(),
            "Hey Doc"
        );

        // ---------------------------------------------------------------------------------------------

        // AES ECB 128 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-128-ecb --base64 -K '00112233445566778899AABBCCDDEEFF'
        assert_eq!(
            aes_128_ecb_encrypt(key_128, "Hey Doc", false).unwrap(),
            "iYb0EyQStjUulA4sfAA4jw=="
        );

        // AES ECB 128 decryption
        // echo 'iYb0EyQStjUulA4sfAA4jw==' | openssl enc -d -aes-128-ecb --base64 -K '00112233445566778899AABBCCDDEEFF'
        assert_eq!(
            aes_128_ecb_decrypt(key_128, "iYb0EyQStjUulA4sfAA4jw==", false).unwrap(),
            "Hey Doc"
        );

        // AES ECB 192 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-192-ecb --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677'
        assert_eq!(
            aes_192_ecb_encrypt(key_192, "Hey Doc", false).unwrap(),
            "3wviCl5mie4Ub4sS7X7STw=="
        );

        // AES ECB 192 decryption
        // echo '3wviCl5mie4Ub4sS7X7STw==' | openssl enc -d -aes-192-ecb --base64 -K '00112233445566778899AABBCCDDEEFF0011223344556677'
        assert_eq!(
            aes_192_ecb_decrypt(key_192, "3wviCl5mie4Ub4sS7X7STw==", false).unwrap(),
            "Hey Doc"
        );

        // AES ECB 256 encryption
        // echo -n 'Hey Doc' | openssl enc -aes-256-ecb --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
        assert_eq!(
            aes_256_ecb_encrypt(key_256, "Hey Doc", false).unwrap(),
            "1wI8/eKQIzIRSdm+eSx4kw=="
        );

        // AES ECB 256 decryption
        // echo '1wI8/eKQIzIRSdm+eSx4kw==' | openssl enc -d -aes-256-ecb --base64 -K '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
        assert_eq!(
            aes_256_ecb_decrypt(key_256, "1wI8/eKQIzIRSdm+eSx4kw==", false).unwrap(),
            "Hey Doc"
        );

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
