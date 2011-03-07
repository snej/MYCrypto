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

@class MYPublicKey, MYIdentity, MYCertificateInfo, MYSHA1Digest;


/** An X.509 certificate. */
@interface MYCertificate : MYKeychainItem {
    @private
    SecCertificateRef _certificateRef;
    MYCertificateInfo *_info;
}

/** Creates a MYCertificate object for an existing Keychain certificate reference. */
+ (MYCertificate*) certificateWithCertificateRef: (SecCertificateRef)certificateRef;

/** Initializes a MYCertificate object for an existing Keychain certificate reference. */
- (id) initWithCertificateRef: (SecCertificateRef)certificateRef;

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data;

/** Checks whether two MYCertificate objects have bit-for-bit identical certificate data. */
- (BOOL)isEqualToCertificate:(MYCertificate*)cert;

/** The Keychain object reference for this certificate. */
@property (readonly) SecCertificateRef certificateRef;

/** The certificate's data. */
@property (readonly) NSData *certificateData;

/** The certificate's public key. */
@property (readonly) MYPublicKey *publicKey;

/** The certificate's public key's SHA-1 digest. */
@property (readonly) MYSHA1Digest *publicKeyDigest;

/** The Identity (if any) that this Certificate is part of. */
@property (readonly) MYIdentity *identity;

/** The metadata of the certificate, like the subject name and expiration date. */
@property (readonly) MYCertificateInfo *info;

/** The common name of the subject (owner) of the certificate. */
@property (readonly) NSString *commonName;

/** The list (if any) of the subject's email addresses. */
@property (readonly) NSArray *emailAddresses;

- (SecTrustResultType) evaluateTrustWithPolicy: (SecPolicyRef)policy;
- (SecTrustResultType) evaluateTrust;

- (SecTrustSettingsResult) userTrustSettingsForPolicy: (SecPolicyRef)policy
                                               string: (NSString*) policyString;


/** @name Mac-Only
 *  Functionality not available on iPhone. 
 */
//@{
#if !TARGET_OS_IPHONE

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding;

/** Finds the current 'preferred' certificate for the given name string. */
+ (MYCertificate*) preferredCertificateForName: (NSString*)name;

/** Associates the receiver as the preferred certificate for the given name string. */
- (BOOL) setPreferredCertificateForName: (NSString*)name;

#endif
//@}


/** @name Expert
 */
//@{

+ (SecPolicyRef) X509Policy;
+ (SecPolicyRef) SSLPolicy;

#if !TARGET_OS_IPHONE
+ (SecPolicyRef) SMIMEPolicy;
- (CSSM_CERT_TYPE) certificateType;
- (NSArray*) trustSettings;
- (BOOL) setUserTrust: (SecTrustUserSetting)trustSetting;
#endif
    
//@}
    
@end


NSString* MYTrustResultDescribe( SecTrustResultType result );
#if !TARGET_OS_IPHONE
NSString* MYPolicyGetName( SecPolicyRef policy );
NSString* MYTrustDescribe( SecTrustRef trust );
#endif
