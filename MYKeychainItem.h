//
//  MYKeychainItem.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/26/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
@class MYKeychain;


/** Error domain for CSSM (low-level crypto) errors */
extern NSString* const MYCSSMErrorDomain;


#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
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
}

/** The Keychain item reference that this object represents. */
@property (readonly) MYKeychainItemRef keychainItemRef;

/** The Keychain that contains this object, or nil. */
@property (readonly) MYKeychain *keychain;

/** Removes the item from its keychain, if any. */
- (BOOL) removeFromKeychain;

@end
