//
//  MYKeychainItem.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/26/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "MYCryptoConfig.h"
@class MYKeychain;


/** Error domain for CSSM (low-level crypto) errors */
extern NSString* const MYCSSMErrorDomain;


#if MYCRYPTO_USE_IPHONE_API
typedef CFTypeRef MYKeychainItemRef;
#else
typedef SecKeychainItemRef MYKeychainItemRef;
#endif


/** Abstract base class for keychain items.
    Direct subclasses are MYKey and MYCertificate. */
@interface MYKeychainItem : NSObject
{
    @private
    MYKeychainItemRef _itemRef;
#if MYCRYPTO_USE_IPHONE_API
    BOOL _isPersistent;
#endif
}

/** The Keychain item reference that this object represents. */
@property (readonly) MYKeychainItemRef keychainItemRef;

/** The Keychain that contains this object, or nil. */
@property (readonly) MYKeychain *keychain;

/** Removes the item from its keychain, if any. */
- (BOOL) removeFromKeychain;

#if MYCRYPTO_USE_IPHONE_API
@property BOOL isPersistent;
#endif

@end
