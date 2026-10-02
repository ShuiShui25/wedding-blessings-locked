山海同庆 · 亲友专属

This repository contains only the password-entry interface and an authenticated encrypted website bundle.
Names, photographs, map content, and the site password are not published in plaintext.

Encryption: AES-256-GCM; password derivation: PBKDF2-HMAC-SHA256, 600,000 iterations.
A randomly generated, unique access password is distributed privately to invited guests.
The browser decrypts the website in memory. It does not save passwords or decryption keys in browser storage.

Encryption cannot prevent an authorized visitor from saving, taking screenshots, or redistributing decrypted content.

Third-party library license: third-party-licenses.txt.
