//
//  MYCertificate.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/26/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeychainItem.h"

#if !TARGET_OS_IPHONE
#import <Security/cssmtype.h>
#endif

@class MYPublicKey;


/** An X.509 certificate. */
@interface MYCertificate : MYKeychainItem {
    SecCertificateRef _certificateRef;
}

/** Creates a MYCertificate object for an existing Keychain certificate reference. */
- (id) initWithCertificateRef: (SecCertificateRef)certificateRef;

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data;

#if !TARGET_OS_IPHONE
/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding;
#endif

/** The Keychain object reference for this key. */
@property (readonly) SecCertificateRef certificateRef;

/** The certificate's data. */
@property (readonly) NSData *certificateData;

/** The certificate's public key. */
@property (readonly) MYPublicKey *publicKey;

@property (readonly) NSString *commonName;
@property (readonly) NSArray *emailAddresses;

#if !TARGET_OS_IPHONE
/** Finds the current 'preferred' certificate for the given name string. */
+ (MYCertificate*) preferredCertificateForName: (NSString*)name;

/** Associates the receiver as the preferred certificate for the given name string. */
- (BOOL) setPreferredCertificateForName: (NSString*)name;
#endif

@end
