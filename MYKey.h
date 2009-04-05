//
//  MYKey.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeychainItem.h"


@protocol MYEncryption <NSObject>

/** Encrypts data using this key, returning the raw encrypted result. */
- (NSData*) encryptData: (NSData*)data;

@end

@protocol MYDecryption <NSObject>

/** Decrypts data using this key, returning the original data. */
- (NSData*) decryptData: (NSData*)data;

@end



/** Abstract superclass for keys.
    Concrete subclasses are MYSymmetricKey and MYPublicKey. */
@interface MYKey : MYKeychainItem

/** The key's raw data. */
@property (readonly) NSData *keyData;

/** The user-visible name (kSecKeyPrintName) associated with this key in the Keychain.
    The user can edit this, so don't expect it to be immutable. */
@property (copy) NSString *name;

/** An application-specific string (kSecKeyAlias) associated with this key in the Keychain.
    Not visible to or editable by the user.
    If you own this key, you can store any associated metadata you like here, although be aware
    that it can be read and modified by any other app that can access this key. */
@property (copy) NSString *alias;

#if !TARGET_OS_IPHONE
/** The user-visible comment (kSecKeyApplicationTag) associated with this key in the Keychain.
    The user can edit this, so don't expect it to be immutable. */
@property (copy) NSString *comment;
#endif

@end



@interface MYKey (Expert)

/** Creates a MYKey object for an existing Keychain key reference.
    This is abstract -- must be called on a MYSymmetricKey or MYPublicKey, as appropriate. */
- (id) initWithKeyRef: (SecKeyRef)keyRef;

/** The Keychain object reference for this key. */
@property (readonly) SecKeyRef keyRef;

#if !TARGET_OS_IPHONE
/** The underlying CSSM_KEY structure; used with low-level crypto APIs. */
@property (readonly) const struct cssm_key* cssmKey;

/** Converts the key into a data blob in one of several standard formats, suitable for storing in
    a file or sending over the network.
    @param format  The data format: kSecFormatOpenSSL, kSecFormatSSH, kSecFormatBSAFE or kSecFormatSSHv2.
    @param withPEM  YES if the data should be encoded in PEM format, which converts into short lines
        of printable ASCII characters, suitable for sending in email. */
- (NSData*) exportKeyInFormat: (SecExternalFormat)format withPEM: (BOOL)withPEM;
#endif

@end
