# MYCrypto #

Version 0.51 — 12 May 2012

By [Jens Alfke](mailto:jens@mooseyard.com)

## Introduction ##

**MYCrypto** is a high-level cryptography API for Mac OS X and iPhone. It's an Objective-C wrapper around the system
**[Keychain](http://developer.apple.com/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html#//apple_ref/doc/uid/TP30000897-CH204-TP9)**
and **CSSM** APIs, which are notoriously hard to use, as well as **CommonCrypto**, which is easier but quite limited.

MYCrypto gives you easy object-oriented interfaces to:

* Symmmetric cryptography (session keys and password-based encryption)
* Asymmetric cryptography (public and private keys; digital signatures)
* Creating and managing X.509 certificates (for use with SSL, S/MIME and CMS)
* Cryptographic digests/hashes (effectively-unique IDs for data)
* The Keychain (a secure, encrypted storage system for keys and passwords)
* Cryptographic Message Syntax [CMS] for signing/encrypting data
* Parsing and generating ASN.1, BER and DER (the weird binary data formats used by crypto standards)

It's open source, released under a friendly BSD license.

## Setup ##

Kindly direct your eyes to the **[Setup](https://bitbucket.org/snej/mycrypto/wiki/Setup)** page...

## Overview ##

The [class hierarchy](https://bytebucket.org/snej/mycrypto/wiki/Documentation/html/hierarchy.html) of MYCrypto looks like this:

* MYKeychain
* _MYKeychainItem_
  * _MYKey_
      * MYSymmetricKey
      * MYPublicKey
      * MYPrivateKey
      * MYCertificate
      * MYIdentity
* _MYDigest_
  * MYSHA1Digest
  * MYSHA256Digest
* MYCryptor
* MYEncoder
* MYDecoder
* MYSigner
* MYCertificateInfo
  * MYCertificateRequest

(_Italicized_ classes are abstract.)

## Examples ##

Please see the [Examples](https://bitbucket.org/snej/mycrypto/wiki/Examples) page.

## Current Limitations ##

* Certificate generation only supports self-signed certs, not cert requests sent to an external signer.
* Some functionality doesn't work on iPhone. The security APIs in iOS are new and rather poorly documented and poorly understood by me. Specifically, anything involving keys not stored in a keychain is unlikely to work. This is mostly an issue with symmetric session keys.

### Current API limitations, to be remedied in the future: ###

* No API for accessing Keychain passwords; fortunately there are several other utility libraries that provide this. And if your code is doing cryptographic operations, it probably needs to store the keys themselves, not passwords.
* Error reporting is too limited. Most methods indicate an error by returning nil, NULL or NO, but don't provide the standard "out" NSError parameter to provide more information. Expect the API to be refactored eventually to remedy this.
* Some functionality is not available on iOS, generally because there is no underlying API for it on that platform, or because the API is different from the Mac OS API and I haven't written wrapper code for it yet.

## References ##

* [_Security Overview_](http://developer.apple.com/documentation/Security/Conceptual/Security_Overview/Introduction/Introduction.html) (Apple)
* [_Secure Coding Guide_](http://developer.apple.com/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html) (Apple)

* [_Common Security: CDSA and CSSM, Version 2_](http://www.opengroup.org/publications/catalog/c914.htm) (The Open Group)
* [RFC 3280: Internet X.509 Certificate Profile](http://tools.ietf.org/html/rfc3280)
* [A Layman's Guide to a Subset of ASN.1, BER, and DER](http://www.columbia.edu/~ariel/ssleay/layman.html) (Burton S. Kaliski Jr.)
* [X.509 Style Guide](http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt) (Peter Gutmann)

* [_Practical Cryptography_](http://www.schneier.com/book-practical.html) (Ferguson and Schneier)
* [_Handbook of Applied Cryptography_](http://www.cacr.math.uwaterloo.ca/hac/) (Menezes, van Oorschot, Vanstone) — free download!
* [_The Devil's InfoSec Dictionary_](http://www.csoonline.com/article/220527/The_Devil_s_Infosec_Dictionary) (CSO Online)