//
//  MYCertificate.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/26/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCertificate.h"
#import "MYCrypto_Private.h"
#import "MYIdentity.h"
#import "MYDigest.h"
#import "MYCertificateInfo.h"
#import "MYErrorUtils.h"


@interface MYCertificate ()
- (BOOL) _verify;
@end



@implementation MYCertificate


/** Creates a MYCertificate object for an existing Keychain certificate reference. */
- (id) initWithCertificateRef: (SecCertificateRef)certificateRef {
    self = [super initWithKeychainItemRef: (SecKeychainItemRef)certificateRef];
    if (self) {
        _certificateRef = certificateRef;     // superclass has already CFRetained it
        if (self.certificateData.length == 0) {
            return nil;
        }
        if (![self _verify]) {
            Log(@"Self-signed cert failed signature verification (%@)", self);
            return nil;
        }
    }
    return self;
}

+ (MYCertificate*) certificateWithCertificateRef: (SecCertificateRef)certificateRef {
    return [[self alloc] initWithCertificateRef: certificateRef];
}

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data
#if !MYCRYPTO_USE_IPHONE_API
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding
#endif
{
    Assert(data);
    SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
    if (!certificateRef) {
        return nil;
    }
    self = [self initWithCertificateRef: certificateRef];
    CFRelease(certificateRef);
    
    if (self && ![self _verify]) {
          Log(@"Self-signed cert failed signature verification (%@)", self);
          return nil;
    }
    
    return self;
}

#if !MYCRYPTO_USE_IPHONE_API
- (id) initWithCertificateData: (NSData*)data {
    return [self initWithCertificateData: data 
                                    type: CSSM_CERT_X_509v3
                                encoding: CSSM_CERT_ENCODING_BER];
}
#endif




- (NSString*) description {
    return $sprintf(@"%@[%@ %@/%p]", 
                    [self class],
                    self.commonName,
                    self.certificateData.my_SHA1Digest.abbreviatedHexString,
                    _certificateRef);
}


- (BOOL)isEqualToCertificate:(MYCertificate*)cert {
    return [self isEqual: cert] || [self.certificateData isEqual: cert.certificateData];
}


#if !TARGET_OS_IPHONE
+ (MYCertificate*) preferredCertificateForName: (NSString*)name {
    SecCertificateRef certRef = NULL;
    if (!check(SecCertificateCopyPreference((__bridge CFStringRef)name, 0, &certRef),
               @"SecCertificateCopyPreference"))
        return nil;
    MYCertificate* result = [[MYCertificate alloc] initWithCertificateRef: certRef];
    CFRelease(certRef);
    return result;
}

- (BOOL) setPreferredCertificateForName: (NSString*)name {
    return check(SecCertificateSetPreference(_certificateRef, (__bridge CFStringRef)name, 0, NULL),
                 @"SecCertificateSetPreference");
}
#endif //TARGET_OS_IPHONE


@synthesize certificateRef=_certificateRef;

- (NSData*) certificateData {
    CFDataRef data = SecCertificateCopyData(_certificateRef);
    return data ? (id)CFBridgingRelease(data) :nil;
}

- (MYPublicKey*) publicKey {
    SecKeyRef keyRef = NULL;
#if MYCRYPTO_USE_IPHONE_API
    SecTrustRef trust = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    NSArray* certs = @[(__bridge id)_certificateRef];
    OSStatus err = SecTrustCreateWithCertificates((__bridge CFArrayRef)certs,
                                                  policy,
                                                  &trust);
    CFRelease(policy);
    if (!check(err,@"SecTrustCreateWithCertificates"))
        return nil;
    SecTrustResultType result;
    if (!check(SecTrustEvaluate(trust, &result), @"SecTrustEvaluate")) {
        CFRelease(trust);
        return nil;
    }
    keyRef = SecTrustCopyPublicKey(trust);
    CFRelease(trust);
#else
    if (!check(SecCertificateCopyPublicKey(_certificateRef, &keyRef),
               @"SecCertificateCopyPublicKey") || !keyRef)
        return nil;
#endif
    if (!keyRef)
        return nil;
    MYPublicKey *key = [[MYPublicKey alloc] initWithKeyRef: keyRef];
    CFRelease(keyRef);
#if MYCRYPTO_USE_IPHONE_API
    key.certificate = self;
    key.isPersistent = NO;
#endif
    return key;
}

- (MYSHA1Digest*) publicKeyDigest {
    return self.publicKey.publicKeyDigest;
}

- (MYIdentity*) identity {
    return [[MYIdentity alloc] initWithCertificateRef: _certificateRef];
}

- (MYCertificateInfo*) info {
    if (!_info) {
        NSError *error = nil;
        NSData* data = self.certificateData;
        if (data) {
            _info = [[MYCertificateInfo alloc] initWithCertificateData: data
                                                                 error: &error];
        }
        if (!_info)
            Warn(@"Couldn't parse certificate %@: %@", self, error);
    }
    return _info;
}

- (NSString*) commonName {
    CFStringRef name = NULL;
#if MYCRYPTO_USE_IPHONE_API
    name = SecCertificateCopySubjectSummary(_certificateRef);
#else
    if (!check(SecCertificateCopyCommonName(_certificateRef, &name),
               @"SecCertificateCopyCommonName"))
        return nil;
#endif
    return name ? (NSString*)CFBridgingRelease(name) : nil;
}

- (NSArray*) emailAddresses {
#if MYCRYPTO_USE_IPHONE_API
    NSString *email = self.info.subject.emailAddress;
    return email ?@[email] :nil;
#else
    CFArrayRef addrs = NULL;
    if (!check(SecCertificateCopyEmailAddresses(_certificateRef, &addrs),
               @"SecCertificateCopyEmailAddresses") || !addrs)
        return nil;
    return (NSArray*)CFBridgingRelease(addrs);
#endif
}


#if !MYCRYPTO_USE_IPHONE_API
+ (NSArray*) readCertificatesFromData: (NSData*)data
                               format: (SecExternalFormat)format
{
    SecKeyImportExportParameters params = {};
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = kSecKeySecurePassphrase;
    params.keyAttributes = CSSM_KEYATTR_EXTRACTABLE;
    params.keyUsage = CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_SIGN;

    SecExternalItemType type = kSecItemTypeAggregate;
    CFArrayRef items;
    if (!check(SecKeychainItemImport((__bridge CFDataRef)data, NULL, &format, &type,
                                     0, &params, NULL, &items),
               @"SecKeychainItemImport"))
        return NULL;
    if (!items)
        return NULL;
    if (CFArrayGetCount(items) == 0 || type != kSecItemTypeAggregate) {
        CFRelease(items);
        return NULL;
    }
    
    Log(@"Read %lu items from data:", CFArrayGetCount(items)); //TEMP
    NSMutableArray* result = $marray();
    for (int i=0; i<CFArrayGetCount(items); i++) {
        CFTypeRef item = CFArrayGetValueAtIndex(items,i);
        Log(@"    item #%i: %@", i, item);  //TEMP
        CFTypeID type = CFGetTypeID(item);
        MYKeychainItem* object = nil;
        if (type == SecCertificateGetTypeID()) {
            object = [[self alloc] initWithCertificateRef: (SecCertificateRef)item];
        }
        if (object)
            [result addObject: object];
    }
    CFRelease(items);
    return result;       
}
#endif


#pragma mark -
#pragma mark TRUST/POLICY STUFF:


- (BOOL) _verify {
    if (self.certificateData.length == 0)
        return NO;
    // If the cert is self-signed, verify its signature. Apple's frameworks don't do this,
    // even the SecTrust API; if the signature doesn't verify, they just assume it could be
    // signed by a different cert. Seems like a bad decision to me, so I'll add the check:
    MYCertificateInfo *info = self.info;
    return info && (!info.isRoot || [info verifySignatureWithKey: self.publicKey]);
}


- (SecTrustResultType) evaluateTrustWithPolicy: (SecPolicyRef)policy {
    SecTrustRef trust;
    NSArray* certs = @[(__bridge id)_certificateRef];
    if (!check(SecTrustCreateWithCertificates((__bridge CFArrayRef)certs, policy, &trust),
               @"SecTrustCreateWithCertificates"))
        return kSecTrustResultOtherError;
    SecTrustResultType result;
    if (!check(SecTrustEvaluate(trust, &result), @"SecTrustEvaluate"))
        result = kSecTrustResultOtherError;
    
#if !MYCRYPTO_USE_IPHONE_API
    // This is just to log details:
#if 0
    CSSM_TP_APPLE_EVIDENCE_INFO *status;
    CFArrayRef certChain;
    if (check(SecTrustGetResult(trust, &result, &certChain, &status), @"SecTrustGetResult")) {
        Log(@"evaluateTrust: result=%@, bits=0x%X, certChain=%@", MYTrustResultDescribe(result),status->StatusBits, certChain);
        for (unsigned i=0; i<status->NumStatusCodes; i++)
            Log(@"    #%i: %X", i, status->StatusCodes[i]);
        CFRelease(certChain);
    }
#endif
#endif
    
    CFRelease(trust);
    return result;
}

- (SecTrustResultType) evaluateTrust {
    return [self evaluateTrustWithPolicy: [[self class] X509Policy]];
}


#if !MYCRYPTO_USE_IPHONE_API
+ (SecPolicyRef) policyForOID: (CSSM_OID) policyOID {
    SecPolicySearchRef search;
    if (!check(SecPolicySearchCreate(CSSM_CERT_X_509v3, &policyOID, NULL, &search),
           @"SecPolicySearchCreate"))
        return nil;
    SecPolicyRef policy = NULL;
    if (!check(SecPolicySearchCopyNext(search, &policy), @"SecPolicySearchCopyNext"))
        policy = NULL;
    CFRelease(search);
    return policy;
}
#endif

+ (SecPolicyRef) X509Policy {
    static SecPolicyRef sX509Policy = NULL;
    if (!sX509Policy) {
#if MYCRYPTO_USE_IPHONE_API
        sX509Policy = SecPolicyCreateBasicX509();
#else
        sX509Policy = [self policyForOID: CSSMOID_APPLE_X509_BASIC];
#endif
    }
    return sX509Policy;
}

+ (SecPolicyRef) SSLPolicy {
    static SecPolicyRef sSSLPolicy = NULL;
    if (!sSSLPolicy) {
#if MYCRYPTO_USE_IPHONE_API
        sSSLPolicy = SecPolicyCreateSSL(NO,NULL);
#else
        sSSLPolicy = [self policyForOID: CSSMOID_APPLE_TP_SSL];
#endif
    }
    return sSSLPolicy;
}

#if !TARGET_OS_IPHONE
+ (SecPolicyRef) SMIMEPolicy {
    static SecPolicyRef sSMIMEPolicy = NULL;
    if (!sSMIMEPolicy) {
        sSMIMEPolicy = [self policyForOID: CSSMOID_APPLE_TP_SMIME];
    }
    return sSMIMEPolicy;
}

- (CSSM_CERT_TYPE) certificateType {
    CSSM_CERT_TYPE type = CSSM_CERT_UNKNOWN;
    if (!check(SecCertificateGetType(_certificateRef, &type), @"SecCertificateGetType"))
        type = CSSM_CERT_UNKNOWN;
    return type;
}

- (NSArray*) trustSettings {
    CFArrayRef settings = NULL;
    OSStatus err = SecTrustSettingsCopyTrustSettings(_certificateRef, kSecTrustSettingsDomainUser, 
                                                     &settings);
    if (err == errSecItemNotFound || !check(err,@"SecTrustSettingsCopyTrustSettings") || !settings)
        return nil;
    return (NSArray*)CFBridgingRelease(settings);
}

- (SecTrustSettingsResult) userTrustSettingsForPolicy: (SecPolicyRef)policy
                                               string: (NSString*) policyString
                                              options: (NSStringCompareOptions)compareOptions
{
    for( NSDictionary* setting in [self trustSettings]) {
        if (![setting[(id)kSecTrustSettingsPolicy] isEqual: (__bridge id)policy])
            continue;
        if (policyString) {
            // Policy string may end with a NUL byte, so trim it
            NSString* certPolicy = setting[(id)kSecTrustSettingsPolicyString];
            if (!certPolicy)
                continue;
            certPolicy = [certPolicy stringByTrimmingCharactersInSet: [NSCharacterSet controlCharacterSet]];
            if ([policyString compare: certPolicy options: compareOptions] != 0)
                continue;
        }
        // OK, this entry matches, so check the result:
        NSNumber* result = setting[(id)kSecTrustSettingsResult];
        if (result != nil)
            return [result intValue];
        else
            return kSecTrustSettingsResultTrustRoot;
    }
    return kSecTrustSettingsResultUnspecified;
}


- (BOOL) setUserTrust: (SecTrustUserSetting)trustSetting
{
    if (trustSetting == kSecTrustResultProceed)
        return [self addUserTrustForPolicy: NULL string: nil];
    else if (trustSetting == kSecTrustResultDeny)
        return [self removeUserTrust];
    else
        return NO;
}


- (BOOL) addUserTrustForPolicy: (SecPolicyRef)policy
                        string: (NSString*) string
{
    NSDictionary* settings = nil;
    if (policy) {
        SecTrustSettingsResult result = self.info.isRoot ? kSecTrustSettingsResultTrustRoot
                                                         : kSecTrustSettingsResultTrustAsRoot;
        settings = $dict({(id)kSecTrustSettingsPolicy, (__bridge id)policy},
                         {(id)kSecTrustSettingsPolicyString, string},
                         {(id)kSecTrustSettingsResult, @(result)});
    }
    OSStatus err = SecTrustSettingsSetTrustSettings(_certificateRef, 
                                                    kSecTrustSettingsDomainUser,
                                                    (__bridge CFTypeRef)(settings));
    return err != errAuthorizationCanceled && check(err, @"SecTrustSettingsSetTrustSettings");
}


- (BOOL) removeUserTrust
{
    OSStatus err = SecTrustSettingsRemoveTrustSettings(_certificateRef, 
                                                       kSecTrustSettingsDomainUser);
    if (err == errSecItemNotFound)
        return YES;
    return err != errAuthorizationCanceled && check(err, @"SecTrustSettingsRemoveTrustSettings");
}

#endif


@end


NSString* MYTrustResultDescribe( SecTrustResultType result ) {
    static NSString* const kTrustResultNames[kSecTrustResultOtherError+1] = {
        @"Invalid",
        @"Proceed",
        @"Confirm",
        @"Deny",
        @"Unspecified",
        @"RecoverableTrustFailure",
        @"FatalTrustFailure",
        @"OtherError"
    };
    if (result <=kSecTrustResultOtherError)
        return kTrustResultNames[result];
    else
        return $sprintf(@"(Unknown trust result %lu)", (unsigned long)result);
}


#if !TARGET_OS_IPHONE
NSString* MYPolicyGetName( SecPolicyRef policy ) {
    if (!policy)
        return @"(null)";
    CSSM_OID oid = {};
    SecPolicyGetOID(policy, &oid);
    return $sprintf(@"SecPolicy[%@]", OIDAsString(oid));
}

NSString* MYTrustDescribe( SecTrustRef trust ) {
    SecTrustResultType result;
    CFArrayRef certChain=NULL;
    CSSM_TP_APPLE_EVIDENCE_INFO* statusChain;
    OSStatus err = SecTrustGetResult(trust, &result, &certChain, &statusChain);
    NSString *desc;
    if (err)
        desc = $sprintf(@"SecTrust[%p, err=%@]", trust, MYErrorName(NSOSStatusErrorDomain, err));
    else
        desc = $sprintf(@"SecTrust[%@, %lu in chain]", 
                        MYTrustResultDescribe(result),
                        CFArrayGetCount(certChain));
    if (certChain) CFRelease(certChain);
    return desc;
}


// Taken from Keychain.framework
NSString* OIDAsString(const CSSM_OID oid) {
    if ((NULL == oid.Data) || (0 >= oid.Length)) {
        return nil;
    } else {
        NSMutableString *result = [NSMutableString stringWithCapacity:(4 * oid.Length)];
        unsigned int i;
        
        for (i = 0; i < oid.Length; ++i) {
            [result appendFormat:@"%s%hhu", ((0 == i) ? "" : ", "), oid.Data[i]];
        }
        
        return result;
    }
}
#endif


#if !TARGET_OS_IPHONE
TestCase(Trust) {
    Log(@"X.509 policy = %@", MYPolicyGetName([MYCertificate X509Policy]));
    Log(@"  SSL policy = %@", MYPolicyGetName([MYCertificate SSLPolicy]));
    Log(@"SMIME policy = %@", MYPolicyGetName([MYCertificate SMIMEPolicy]));
    for (MYCertificate *cert in [[MYKeychain defaultKeychain] enumerateCertificates]) {
        NSArray *settings = cert.trustSettings;
        if (settings)
            Log(@"---- %@ = %@", cert, settings);
    }
}
#endif



/*
 Copyright (c) 2009, Jens Alfke <jens@mooseyard.com>. All rights reserved.
 
 Redistribution and use in source and binary forms, with or without modification, are permitted
 provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice, this list of conditions
 and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 and the following disclaimer in the documentation and/or other materials provided with the
 distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND 
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRI-
 BUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
