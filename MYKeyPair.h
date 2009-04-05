//
//  KeyPair.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYPublicKey.h"


/** A key-pair consisting of a public and a private key.
    Can be used for signing and decrypting, as well as the inherited encrypting/verifying. */
@interface MYKeyPair : MYPublicKey <MYDecryption>
{
    SecKeyRef _privateKey;
}

/** Creates a MYKeyPair object from existing Keychain key references. */
- (id) initWithPublicKeyRef: (SecKeyRef)publicKey privateKeyRef: (SecKeyRef)privateKey;

#if !TARGET_OS_IPHONE
/** Exports the private key as a data blob, so that it can be stored as a backup, or transferred
    to another computer. Since the key is sensitive, it must be exported in encrypted form
    using a user-chosen passphrase. This method will display a standard alert panel, run by
    the Security agent, that prompts the user to enter a new passphrase for encrypting the key.
    The same passphrase must be re-entered when importing the key from the data blob.
    @param format  The data format: kSecFormatOpenSSL, kSecFormatSSH, kSecFormatBSAFE or kSecFormatSSHv2.
    @param withPEM  YES if the data should be encoded in PEM format, which converts into short lines
        of printable ASCII characters, suitable for sending in email.
    @param alertTitle  An optional title for the alert panel. (Currently ignored by the OS?)
    @param prompt  An optional prompt message to display in the alert panel. */
- (NSData*) exportPrivateKeyInFormat: (SecExternalFormat)format
                             withPEM: (BOOL)withPEM
                          alertTitle: (NSString*)title
                         alertPrompt: (NSString*)prompt;

/** A convenient shorthand for the full exportPrivateKeyInFormat... method.
    Uses OpenSSL format, wrapped with PEM, and default title and prompt for the alert. */
- (NSData*) exportPrivateKey;
#endif

/** The underlying Keychain key reference for the private key. */
@property (readonly) SecKeyRef privateKeyRef;

/** Decrypts data that was encrypted using the public key. */
- (NSData*) decryptData: (NSData*)data;

/** Generates a signature of data, using the private key.
    The resulting signature can be verified using the matching MYPublicKey's
    verifySignature:ofData: method. */
- (NSData*) signData: (NSData*)data;

@end
