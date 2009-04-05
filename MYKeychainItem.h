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

#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
typedef CFTypeRef MYKeychainItemRef;
#else
typedef SecKeychainItemRef MYKeychainItemRef;
#endif


/** Abstract base class for keychain items: MYPublicKey, MYKeyPair and MYCertificate. */
@interface MYKeychainItem : NSObject
{
    @private
    MYKeychainItemRef _itemRef;
}

- (id) initWithKeychainItemRef: (MYKeychainItemRef)itemRef;

@property (readonly) MYKeychainItemRef keychainItemRef;

@property (readonly) MYKeychain *keychain;

/** Removes the item from its keychain, if any. */
- (BOOL) removeFromKeychain;

@end
