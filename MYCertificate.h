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

/** Checks whether two MYCertificate objects have bit-for-bit identical certificate data.
    (The regular -isEqual: method just calls CFEqual on the underlying SecCertificateRefs,
    which only tells you if they refer to the same underlying Keychain object.) */
- (BOOL)isEqualToCertificate:(MYCertificate*)cert;

/** The Keychain object reference for this certificate. */
@property (readonly) SecCertificateRef certificateRef;

/** The certificate's data. */
@property (readonly) NSData *certificateData;

/** The certificate's public key. */
@property (readonly) MYPublicKey *publicKey;

/** The certificate's public key's SHA-1 digest.
    This is often used as a compact (20-byte) identifier for the certificate. */
@property (readonly) MYSHA1Digest *publicKeyDigest;

/** The Identity (if any) that this Certificate is part of.
    In other words, if the matching private key is in the Keychain, this allows you to reach it. */
@property (readonly) MYIdentity *identity;

/** The metadata of the certificate, like the subject name, expiration date and capabilities. */
@property (readonly) MYCertificateInfo *info;

/** The common name of the subject (owner) of the certificate. */
@property (readonly) NSString *commonName;

/** The list (if any) of the subject's email addresses. */
@property (readonly) NSArray *emailAddresses;

/** Determines whether the certificate is trusted for general use.
    (This is really just a convenience that calls -evaluateTrustWithPolicy: using the X509Policy.
    If you have a specific purpose for using the certificate, it's better to call that method
    directly passing in the corresponding policy object.) */
- (SecTrustResultType) evaluateTrust;

/** Determines whether the certificate is trusted for the purpose indicated by the policy.
    For example, if evaluating a cert found in an email you'd use SMIMEPolicy, or for an SSL
    connection you'd use SSLPolicy.
      This does NOT consider user trust overrides, only intrinsic trust. Call
    -userTrustSettingsForPolicy:string: to check user trust settings.
    @param policy  The policy (i.e. usage) you want to evaluate. You'll generally pass the result
            of the class method X509Policy, SSLPolicy or SMIMEPolicy.
    @return  kSecTrustResultProceed means the cert is trusted; kSecTrustResultUnspecified or
            kSecTrustResultRecoverableTrustFailure generally means the cert is (or is issued by)
            a self-signed root that isn't in the system trust list. */
- (SecTrustResultType) evaluateTrustWithPolicy: (SecPolicyRef)policy;

+ (SecPolicyRef) X509Policy;
+ (SecPolicyRef) SSLPolicy;
#if !TARGET_OS_IPHONE
+ (SecPolicyRef) SMIMEPolicy;
#endif


/** @name Mac-Only
 *  Functionality not available on iPhone. 
 */
//@{
#if !TARGET_OS_IPHONE

/** Reads multiple certificates from an aggregate file -- see the system docs for SecExternalFormat for a list of available file types. The returned certificates are not added to a keychain.
    Don't use this for PKCS12 (.p12) files, because those are encrypted and include private keys as well -- for those, you should call -[MYKeychain importIdentity:].
    @param data  The contents of the archive file.
    @param format  The file format, if known. Typically kSecFormatPEMSequence or kSecFormatPKCS7.
    @return  An array of MYCertificate objects. */
+ (NSArray*) readCertificatesFromData: (NSData*)data
                               format: (SecExternalFormat)format;

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding;

/** Finds the current 'preferred' certificate for the given name string. */
+ (MYCertificate*) preferredCertificateForName: (NSString*)name;

/** Associates the receiver as the preferred certificate for the given name string. */
- (BOOL) setPreferredCertificateForName: (NSString*)name;

/** Looks up the user-configured custom trust setings for this certificate: the ones that are
    accessible in apps like Keychain Access and Mail.
    @param policy  The policy object indicating what you want to use this certificate for. For general-purpose use, pass X509Policy.
    @param policyString  A policy-specific parameter. For example, SMIMEPolicy interprets this as the sender's email address, and SSLPolicy interprets it as the peer's hostname.
    @result  The trust setting. If kSecTrustSettingsResultTrustRoot or kSecTrustSettingsResultTrustAsRoot, the user has explicitly marked this cert as trusted for this policy and policyString. */
- (SecTrustSettingsResult) userTrustSettingsForPolicy: (SecPolicyRef)policy
                                               string: (NSString*) policyString
                                              options: (NSStringCompareOptions)compareOptions;

#endif
//@}


/** @name Expert
 */
//@{

#if !TARGET_OS_IPHONE
/** The specific certificate type. Almost always CSSM_CERT_X_509v1 or CSSM_CERT_X_509v3. */
- (CSSM_CERT_TYPE) certificateType;
/** Returns the full list of user-specified trust settings.
    @return  An array of dictionaries; see the system docs for SecTrustSettingsCopyTrustSettings. */
- (NSArray*) trustSettings;
/** Marks a self-signed root cert as fully trusted or not trusted for all purposes.
    NOTE: This call will block while it waits for user confirmation (including an admin password).
    @param trustSetting  Either kSecTrustResultProceed (to mark as trusted) or kSecTrustResultDeny (to mark as untrusted).
    @return  YES on success, NO on failure (most likely the user canceling). */
- (BOOL) setUserTrust: (SecTrustUserSetting)trustSetting;
/** Marks a certificate as trusted by the user for a specific purpose.
    NOTE: This call will block while it waits for user confirmation (including an admin password).
    @param policy  The policy object for the type of usage (e.g. email or SSL).
    @param policyString  A policy-specific parameter. For example, SMIMEPolicy interprets this as the sender's email address, and SSLPolicy interprets it as the peer's hostname.
    @return  YES on success, NO on failure (most likely the user canceling). */
- (BOOL) addUserTrustForPolicy: (SecPolicyRef)policy
                        string: (NSString*)policyString;
/** Remove any user-configured trust for this certificate.
    NOTE: This call will block while it waits for user confirmation (including an admin password).
    @return  YES on success, NO on failure (most likely the user canceling). */
- (BOOL) removeUserTrust;
#endif
    
//@}
    
@end


/** Returns a string describing a SecTrustResultType for debugging purposes, e.g. "Proceed", "RecoverableTrustFailure". */
NSString* MYTrustResultDescribe( SecTrustResultType result );
#if !TARGET_OS_IPHONE
/** Returns a string describing a SecPolicyRef for debugging purposes. Generally this is just a dump of its OID. */
NSString* MYPolicyGetName( SecPolicyRef policy );
 /** Returns a string describing a SecTrustRef for debugging purposes. */
NSString* MYTrustDescribe( SecTrustRef trust );
#endif
