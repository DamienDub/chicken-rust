// A dependency graph that contains any wasm must all be imported
// asynchronously. This `bootstrap.js` file does the single async import, so
// that no one else needs to worry about it again.
import('chicken-rust').then(chickenRust => {

  document.write("<h1>Welcome to chicken rust</h1>");

  document.write("<h2>Here's a SHA-1 made in rust: " + chickenRust.sha1("test") + "</h2>");

  let base64_encoded = chickenRust.base64_encode("test")
  document.write("<h2>Here's a base 64 encoded string: " + base64_encoded + "</h2>");

  try {
    let base64_decoded = chickenRust.base64_decode(base64_encoded)
    document.write("<h2>Here's a base 64 decoded string: " + base64_decoded + "</h2>");
  }
  catch (error) {
    console.error(error);
  }

  let url_encoded = chickenRust.url_encode("https://chickenrust.com?var= Go go go");
  document.write("<h2>Here's an encoded URL string: " + url_encoded + "</h2>");

  try {
    let url_decoded = chickenRust.url_decode(url_encoded);
    document.write("<h2>Here's an decoded URL string: " + url_decoded + "</h2>");
  }
  catch (error) {
    console.error(error);
  }

  try {
    let result = chickenRust.aes_encrypt();
    document.write("<h2>Encryption: " + result + "</h2>");
  }
  catch (error) {
    console.error(error);
  }

}).catch(error => {
  console.error(error);
});


