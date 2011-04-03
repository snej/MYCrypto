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
        if (![self _verify]) {
            Log(@"Self-signed cert failed signature verification (%@)", self);
            [self release];
            return nil;
        }
    }
    return self;
}

+ (MYCertificate*) certificateWithCertificateRef: (SecCertificateRef)certificateRef {
    return [[[self alloc] initWithCertificateRef: certificateRef] autorelease];
}

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data
#if !MYCRYPTO_USE_IPHONE_API
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding
#endif
{
    Assert(data);
    SecCertificateRef certificateRef = NULL;
#if MYCRYPTO_USE_IPHONE_API
    certificateRef = SecCertificateCreateWithData(NULL, (CFDataRef)data);
#else
    CSSM_DATA cssmData = {.Data=(void*)data.bytes, .Length=data.length};
    if (!check(SecCertificateCreateFromData(&cssmData, type, encoding, &certificateRef),
               @"SecCertificateCreateFromData"))
        certificateRef = NULL;
#endif
    if (!certificateRef) {
        [self release];
        return nil;
    }
    self = [self initWithCertificateRef: certificateRef];
    CFRelease(certificateRef);
    
    if (self && ![self _verify]) {
          Log(@"Self-signed cert failed signature verification (%@)", self);
          [self release];
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

- (void) dealloc
{
    [_info release];
    [super dealloc];
}



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
    if (!check(SecCertificateCopyPreference((CFStringRef)name, 0, &certRef),
               @"SecCertificateCopyPreference"))
        return nil;
    return [[[MYCertificate alloc] initWithCertificateRef: certRef] autorelease];
}

- (BOOL) setPreferredCertificateForName: (NSString*)name {
    return check(SecCertificateSetPreference(_certificateRef, (CFStringRef)name, 0, NULL),
                 @"SecCertificateSetPreference");
}
#endif //TARGET_OS_IPHONE


@synthesize certificateRef=_certificateRef;

- (NSData*) certificateData {
#if MYCRYPTO_USE_IPHONE_API
    CFDataRef data = SecCertificateCopyData(_certificateRef);
    return data ?[(id)CFMakeCollectable(data) autorelease] :nil;
#else
    CSSM_DATA cssmData;
    if (!check(SecCertificateGetData(_certificateRef, &cssmData),
               @"SecCertificateGetData"))
        return nil;
    return [NSData dataWithBytes: cssmData.Data length: cssmData.Length];
#endif
}

- (MYPublicKey*) publicKey {
    SecKeyRef keyRef = NULL;
#if MYCRYPTO_USE_IPHONE_API
    SecTrustRef trust = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    OSStatus err = SecTrustCreateWithCertificates((CFArrayRef)$array((id)_certificateRef),
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
    MYPublicKey *key = [[[MYPublicKey alloc] initWithKeyRef: keyRef] autorelease];
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
    return [[[MYIdentity alloc] initWithCertificateRef: _certificateRef] autorelease];
}

- (MYCertificateInfo*) info {
    if (!_info) {
        NSError *error;
        _info = [[MYCertificateInfo alloc] initWithCertificateData: self.certificateData
                                                             error: &error];
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
    return name ?[NSMakeCollectable(name) autorelease] :nil;
}

- (NSArray*) emailAddresses {
#if MYCRYPTO_USE_IPHONE_API
    NSString *email = self.info.subject.emailAddress;
    return email ?$array(email) :nil;
#else
    CFArrayRef addrs = NULL;
    if (!check(SecCertificateCopyEmailAddresses(_certificateRef, &addrs),
               @"SecCertificateCopyEmailAddresses") || !addrs)
        return nil;
    return [(id)CFMakeCollectable(addrs) autorelease];
#endif
}


#pragma mark -
#pragma mark TRUST/POLICY STUFF:


- (BOOL) _verify {
  // If the cert is self-signed, verify its signature. Apple's frameworks don't do this,
  // even the SecTrust API; if the signature doesn't verify, they just assume it could be
  // signed by a different cert. Seems like a bad decision to me, so I'll add the check:
  MYCertificateInfo *info = self.info;
  return !info.isRoot || [info verifySignatureWithKey: self.publicKey];
}  


- (SecTrustResultType) evaluateTrustWithPolicy: (SecPolicyRef)policy {
    SecTrustRef trust;
    if (!check(SecTrustCreateWithCertificates((CFArrayRef)$array((id)_certificateRef), policy, &trust), 
               @"SecTrustCreateWithCertificates"))
        return kSecTrustResultOtherError;
    SecTrustResultType result;
    if (!check(SecTrustEvaluate(trust, &result), @"SecTrustEvaluate"))
        result = kSecTrustResultOtherError;
    
#if !MYCRYPTO_USE_IPHONE_API
    // This is just to log details:
    CSSM_TP_APPLE_EVIDENCE_INFO *status;
    CFArrayRef certChain;
    if (check(SecTrustGetResult(trust, &result, &certChain, &status), @"SecTrustGetResult")) {
        Log(@"evaluateTrust: result=%@, bits=0x%X, certChain=%@", MYTrustResultDescribe(result),status->StatusBits, certChain);
        for (unsigned i=0; i<status->NumStatusCodes; i++)
            Log(@"    #%i: %X", i, status->StatusCodes[i]);
        CFRelease(certChain);
    }
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
    return [(id)CFMakeCollectable(settings) autorelease];
}

- (SecTrustSettingsResult) userTrustSettingsForPolicy: (SecPolicyRef)policy
                                               string: (NSString*) policyString
{
    for( NSDictionary* setting in [self trustSettings]) {
        if (![[setting objectForKey: (id)kSecTrustSettingsPolicy] isEqual: (id)policy])
            continue;
        if (policyString)
            if (![policyString isEqual: [setting objectForKey: (id)kSecTrustSettingsPolicyString]])
                continue;
        // OK, this entry matches, so check the result:
        NSNumber* result = [setting objectForKey: (id)kSecTrustSettingsResult];
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
        settings = $dict({(id)kSecTrustSettingsPolicy, (id)policy},
                         {(id)kSecTrustSettingsPolicyString, string},
                         {(id)kSecTrustSettingsResult, $object(result)});
    }
    OSStatus err = SecTrustSettingsSetTrustSettings(_certificateRef, 
                                                    kSecTrustSettingsDomainUser, settings);
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
        return $sprintf(@"(Unknown trust result %i)", result);
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
        desc = $sprintf(@"SecTrust[%@, %u in chain]", 
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
