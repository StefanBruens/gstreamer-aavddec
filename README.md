This package provides an example GStreamer element that implements
decryption of AAX stream

It takes audio (of type "application/x-aavd")
from qtdemux and performs the AES-CBC decryption and outputs the decrypted
content on a source pad.

Requirements
------------
*    gstreamer 1.20.0
*    Openssl >= 1.1

Usage
-----
The decryptor does not implement any key retrieval, but reads the 4 byte key
from a hex string in /tmp/aavd.key.

The aavd.key file must contain nothing but the hex encoded key, e.g.:
    0123abcd

For a method to retrieve your account specific key, see e.g.:

https://github.com/inAudible-NG/audible-activator

The key is not file specific, but is the same for all audio books of
an account. It is not really a key, but more like a password to unlock the
key already contained in the audio file in an obfuscated manner.
