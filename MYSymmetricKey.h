//
//  MYSymmetricKey.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKey.h"
#import <CommonCrypto/CommonCryptor.h>


/** An old-fashioned symmetric key, so named because it both encrypts and decrypts.
    A key can be generated at random, stored in the keychain, or derived from a user-entered
    passphrase.
 
    These days, symmetric encryption is used mostly on local data such as files, with
    passphrases; or as a transient "session key" for data sent between users, with the
    session key itself encrypted in the message using public-key encryption. (The
    MYEncoder/MYDecoder classes manage this second usage, whose details are tricky.) */
@interface MYSymmetricKey : MYKey <MYEncryption, MYDecryption>
{
    @private
#if !MYCRYPTO_USE_IPHONE_API
    CSSM_KEY *_ownedCSSMKey;
#endif
}

/** Initializes a symmetric key from the given key data and algorithm. */
- (id) initWithKeyData: (NSData*)keyData
             algorithm: (CCAlgorithm)algorithm;

/** Randomly generates a new symmetric key, using the given algorithm and key-size in bits.
    The key is not added to any keychain; if you want to keep the key persistently, use
    the method of the same name in the MYKeychain class. */
+ (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm;

/** The key's algorithm. */
@property (readonly) CCAlgorithm algorithm;

/** The key's size/length, in bits. */
@property (readonly) unsigned keySizeInBits;


#if !TARGET_OS_IPHONE

/** Exports the key as a data blob, so that it can be stored as a backup, or transferred
    to another computer. Since the key is sensitive, it must be exported in encrypted form
    using a user-chosen passphrase. This method will display a standard alert panel, run by
    the Security agent, that prompts the user to enter a new passphrase for encrypting the key.
    The same passphrase must be re-entered when importing the key from the data blob. */
 - (NSData*) exportWrappedKeyWithPassphrasePrompt: (NSString*)prompt;

/** Recreates a symmetric key from its wrapped (encrypted) form. The user will be prompted for
    the passphrase to decrypt the key; this must be the same passphrase that was entered when
    wrapping the key, e.g. when -exportWrappedKeyWithPassphrasePrompt: was called. */
- (id) initWithWrappedKeyData: (NSData*)wrappedKeyData;

/** Converts a passphrase into a symmetric key.
    The same passphrase (and salt) will always return the same key, so you can use this method
    to encrypt and decrypt data using a user-entered passphrase, without having to store the key
    itself in the keychain.
    @param alertTitle  A title for the alert (this seems to be ignored by the OS).
    @param prompt  A prompt string displayed in the alert.
    @param creating  Is a new passphrase being created? If YES, the user will have to enter the
        passphrase twice, to check for errors, and the nifty passphrase-strength meter will be
        displayed. If NO, there's only one text-field, and an option to display its contents in
        the clear.
    @param saltObj  An arbitrary value whose data will be mixed in with the passphrase before
        hashing, to perturb the resulting bits. The purpose of this is to make it harder for
        an attacker to brute-force the key using a precompiled list of digests of common
        passwords. Changing the salt changes the key, so you need to pass the same value when
        re-deriving the key as you did when first generating it. */
+ (MYSymmetricKey*) generateFromUserPassphraseWithAlertTitle: (NSString*)alertTitle
                                                 alertPrompt: (NSString*)prompt
                                                    creating: (BOOL)creating
                                                        salt: (id)saltObj;

/** A utility that prompts for a passphrase, using the Security agent's nice modal panel,
    and returns the raw passphrase as a string.
    @param alertTitle  A title for the alert (this seems to be ignored by the OS).
    @param prompt  A prompt string displayed in the alert.
    @param creating  Is a new passphrase being created? 
        (See description in +generateFromUserPassphrase... method.) */
+ (NSString*) promptForPassphraseWithAlertTitle: (NSString*)alertTitle
                                    alertPrompt: (NSString*)prompt
                                       creating: (BOOL)creating;
#endif TARGET_OS_IPHONE

@end
