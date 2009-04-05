//
//  Cryptor.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>


/** Symmetric encryption: a simple Cocoa wrapper for CommonCrypto/commonCryptor.h.
    Provides a streaming interface for encrypting/decrypting data.
    This class will probably be merged into or integrated with MYSymmetricKey. */
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
    size_t _outputExtraBytes;
}

/** Returns a block of cryptographically-random data, suitable for use as a symmetric key.
    (CommonCryptor.h defines constants for key sizes and size-ranges, like kCCKeySizeAES128.) */
+ (NSData*) randomKeyOfLength: (size_t)length;

/** Converts a passphrase into a block of data of the given size, suitable for use as a symmetric key. */
+ (NSData*) keyOfLength: (size_t)lengthInBits fromPassphrase: (NSString*)passphrase;

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
