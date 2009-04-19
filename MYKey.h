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
{ }

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


/** @name Mac-Only
 *  Functionality not available on iPhone. 
 */
//@{
#if !TARGET_OS_IPHONE

/** The user-visible comment (kSecKeyApplicationTag) associated with this key in the Keychain.
 The user can edit this, so don't expect it to be immutable. */
@property (copy) NSString *comment;

#endif
//@}


/** @name Expert
 *  Advanced methods. 
 */
//@{

/** Creates a MYKey object for an existing Keychain key reference.
    This is abstract -- must be called on a MYSymmetricKey or MYPublicKey, as appropriate. */
- (id) initWithKeyRef: (SecKeyRef)keyRef;

/** The Keychain object reference for this key. */
@property (readonly) SecKeyRef keyRef;

#if !TARGET_OS_IPHONE
/** The underlying CSSM_KEY structure; used with low-level crypto APIs. */
@property (readonly) const struct cssm_key* cssmKey;

/** The underlying CSSM_CSP_HANDLE structure; used with low-level crypto APIs. */
@property (readonly) intptr_t /*CSSM_CSP_HANDLE*/ cssmCSPHandle;

@property (readonly) CSSM_ALGORITHMS cssmAlgorithm;

/** Gets CSSM authorization credentials for a specified operation, such as
    CSSM_ACL_AUTHORIZATION_ENCRYPT. This pointer is necessary for creating some CSSM operation
    contexts.
    @param operation  The type of operation you are going to perform (see the enum values in
            cssmType.h.)
    @param type  Specifies whether the operation should be allowed to present a UI. You'll usually
            want to pass kSecCredentialTypeDefault.
    @param outError  Will be set to point to an NSError on failure, or nil on success.
            Pass nil if you don't care about the specific error.
    @return  The access credentials, or NULL on failure. 
            This pointer is valid for as long as you have a reference
            to the key object. Do not free or delete it. */
- (const CSSM_ACCESS_CREDENTIALS*) cssmCredentialsForOperation: (CSSM_ACL_AUTHORIZATION_TAG)operation
                                                          type: (SecCredentialType)type
                                                         error: (NSError**)outError;

#endif
//@}

@end
