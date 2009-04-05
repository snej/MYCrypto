//
//  MYKey.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeychainItem.h"

#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
typedef CFTypeRef SecExternalItemType;
#endif


@interface MYKey : MYKeychainItem
{
    @private
    SecKeyRef _key;
}

/** Creates a MYKey object for an existing Keychain key reference. */
- (id) initWithKeyRef: (SecKeyRef)keyRef;

/** Creates a MYKey object from exported key data, but does not add it to any keychain. */
- (id) initWithKeyData: (NSData*)data;

#if !TARGET_OS_IPHONE
/** Converts the key into a data blob in one of several standard formats, suitable for storing in
    a file or sending over the network.
    @param format  The data format: kSecFormatOpenSSL, kSecFormatSSH, kSecFormatBSAFE or kSecFormatSSHv2.
    @param withPEM  YES if the data should be encoded in PEM format, which converts into short lines
        of printable ASCII characters, suitable for sending in email. */
- (NSData*) exportKeyInFormat: (SecExternalFormat)format withPEM: (BOOL)withPEM;
#endif

/** The Keychain object reference for this key. */
@property (readonly) SecKeyRef keyRef;

/** The key's raw data in OpenSSL format. This is the same as calling
    -exportKeyInFormat: kSecFormatOpenSSL withPEM: NO */
@property (readonly) NSData *keyData;

@property (readonly) SecExternalItemType keyType;

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



@protocol MYEncryption <NSObject>

/** Encrypts data using this key, returning the raw encrypted result. */
- (NSData*) encryptData: (NSData*)data;

@end

@protocol MYDecryption <NSObject>

/** Decrypts data using this key, returning the original data. */
- (NSData*) decryptData: (NSData*)data;

@end
