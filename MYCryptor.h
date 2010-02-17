//
//  Cryptor.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>


/** Symmetric encryption: a streaming interface for encrypting/decrypting data.
    This is a simple Cocoa wrapper for CommonCrypto/commonCryptor.h. It will probably be
    merged into, or integrated with, MYSymmetricKey. */
@interface MYCryptor : NSObject
{
    @private
    NSData *_key;
    CCOperation _operation;
    CCAlgorithm _algorithm;
    CCOptions _options;
    CCCryptorRef _cryptor;
    NSError *_error;
    NSOutputStream *_outputStream;
    NSMutableData *_output;
}

/** Returns a randomly-generated symmetric key of the desired length (in bits).
 *  @param lengthInBits  The length of the desired key, in bits (not bytes).
 */
+ (NSData*) randomKeyOfLength: (size_t)lengthInBits;

/** Converts a passphrase into a symmetric key of the desired length (in bits).
 *  The same passphrase (and salt) will always return the same key, so you can use this method
 *  to encrypt and decrypt data using a user-entered passphrase, without having to store the key
 *  itself in the keychain.
 *  @param lengthInBits  The length of the desired key, in bits (not bytes).
 *  @param passphrase  The user-entered passphrase.
 *  @param salt  An arbitrary value whose description will be appended to the passphrase before
 *          hashing, to perturb the resulting bits. The purpose of this is to make it harder for
 *          an attacker to brute-force the key using a precompiled list of digests of common
 *          passwords. Changing the salt changes the key, so you need to pass the same value when
 *          re-deriving the key as you did when first generating it.
 */
+ (NSData*) keyOfLength: (size_t)lengthInBits
         fromPassphrase: (NSString*)passphrase
                   salt: (id)salt;

/** Creates a MYCryptor configured to encrypt data. */
- (id) initEncryptorWithKey: (NSData*)key
                  algorithm: (CCAlgorithm)algorithm;

/** Creates a MYCryptor configured to decrypt data. */
- (id) initDecryptorWithKey: (NSData*)key
                  algorithm: (CCAlgorithm)algorithm;

/** The encryption/decryption key; same as the 'key' parameter to the initializer. */
@property (readonly) NSData *key;

/** The cipher to use; initial value is the 'algorithm' parameter to the initializer.
    You can change this <i>before</i> the first call to -addData:, but not after. */
@property CCAlgorithm algorithm;

/** Block-mode cipher options; you can set flags to enable PKCS7 padding or ECB mode
    (default is CBC.)
    You can change this <i>before</i> the first call to -addData:, but not after. */
@property CCOptions options;

/** Setting this property tells the cryptor to send its output to the stream,
    instead of accumulating it in the outputData property.
    You can change this <i>before</i> the first call to -addData:, but not after. */
@property (retain) NSOutputStream *outputStream;

/** The error state, if any, of this cryptor.
    After -addData: or -finish: returns NO, check this property. */
@property (readonly, retain) NSError *error;

/** Adds input data.
    @return  YES if the operation succeeded, NO if it failed. */
- (BOOL) addData: (NSData*)data;

/** Finishes up the encryption/decryption and flushes the remaining bytes of output.
    After this is called, you cannot add any more bytes of data.
    @return  YES if the operation succeeded, NO if it failed. */
- (BOOL) finish;

/** The output of the cryptor. Accessing this property implicitly calls -finish, so don't
    do it until you've added all of the input. (And don't add any more input afterwards.)
    This property will be nil if the outputStream property has been set. */
@property (readonly) NSData *outputData;

@end



/** NSError domain for MYCryptor operations. Error code is interpreted as a CCCryptorStatus,
    with additional error code(s) defined below. */
extern NSString* const CryptorErrorDomain;

enum {
    /** Indicates that the outputStream couldn't write all the bytes given to it (this is legal
        behavior for an NSOutputStream, but MYCryptor can't handle this yet.) */
    kMYCryptorErrorOutputStreamChoked = -777000
};
