//
//  MYSymmetricKey.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKey.h"
#import <CommonCrypto/CommonCryptor.h>


@interface MYSymmetricKey : MYKey <MYEncryption, MYDecryption>
{
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
    @param salt  An arbitrary value whose data will be mixed in with the passphrase before
        hashing, to perturb the resulting bits. The purpose of this is to make it harder for
        an attacker to brute-force the key using a precompiled list of digests of common
        passwords. Changing the salt changes the key, so you need to pass the same value when
        re-deriving the key as you did when first generating it. */
 + (MYSymmetricKey*) generateFromUserPassphraseWithAlertTitle: (NSString*)alertTitle
                                                 alertPrompt: (NSString*)prompt
                                                    creating: (BOOL)creating
                                                        salt: (id)saltObj;

/** The key's algorithm. */
@property (readonly) CCAlgorithm algorithm;

/** The key's size/length, in bits. */
@property (readonly) unsigned keySizeInBits;


/** A utility that prompts for a passphrase, using the Security agent's nice modal panel,
    and returns the raw passphrase as a string.
    @param alertTitle  A title for the alert (this seems to be ignored by the OS).
    @param prompt  A prompt string displayed in the alert.
    @param creating  Is a new passphrase being created? 
        (See description in +generateFromUserPassphrase... method.) */
+ (NSString*) promptForPassphraseWithAlertTitle: (NSString*)alertTitle
                                    alertPrompt: (NSString*)prompt
                                       creating: (BOOL)creating;

@end
