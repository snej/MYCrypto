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

#if !MYCRYPTO_USE_IPHONE_API


@implementation MYCertificate


/** Creates a MYCertificate object for an existing Keychain certificate reference. */
- (id) initWithCertificateRef: (SecCertificateRef)certificateRef {
    self = [super initWithKeychainItemRef: (SecKeychainItemRef)certificateRef];
    if (self) {
        _certificateRef = certificateRef;     // superclass has already CFRetained it
    }
    return self;
}

+ (MYCertificate*) certificateWithCertificateRef: (SecCertificateRef)certificateRef {
    return [[[self alloc] initWithCertificateRef: certificateRef] autorelease];
}

/** Creates a MYCertificate object from exported key data, but does not add it to any keychain. */
- (id) initWithCertificateData: (NSData*)data
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding
{
    Assert(data);
    CSSM_DATA cssmData = {.Data=(void*)data.bytes, .Length=data.length};
    SecCertificateRef certificateRef = NULL;
    if (!check(SecCertificateCreateFromData(&cssmData, type, encoding, &certificateRef),
        @"SecCertificateCreateFromData")) {
        [self release];
        return nil;
    }
    self = [self initWithCertificateRef: certificateRef];
    CFRelease(certificateRef);
    return self;
}

- (id) initWithCertificateData: (NSData*)data {
    return [self initWithCertificateData: data 
                                    type: CSSM_CERT_X_509v3 
                                encoding: CSSM_CERT_ENCODING_BER];
}

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


@synthesize certificateRef=_certificateRef;

- (NSData*) certificateData {
    CSSM_DATA cssmData;
    if (!check(SecCertificateGetData(_certificateRef, &cssmData),
               @"SecCertificateGetData"))
        return nil;
    return [NSData dataWithBytes: cssmData.Data length: cssmData.Length];
}

- (MYPublicKey*) publicKey {
    SecKeyRef keyRef = NULL;
    if (!check(SecCertificateCopyPublicKey(_certificateRef, &keyRef),
               @"SecCertificateCopyPublicKey") || !keyRef)
        return nil;
    MYPublicKey *key = [[[MYPublicKey alloc] initWithKeyRef: keyRef] autorelease];
    CFRelease(keyRef);
    return key;
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
    if (!check(SecCertificateCopyCommonName(_certificateRef, &name),
               @"SecCertificateCopyCommonName") || !name)
        return nil;
    return [(id)CFMakeCollectable(name) autorelease];
}

- (NSArray*) emailAddresses {
    CFArrayRef addrs = NULL;
    if (!check(SecCertificateCopyEmailAddresses(_certificateRef, &addrs),
               @"SecCertificateCopyEmailAddresses") || !addrs)
        return nil;
    return [(id)CFMakeCollectable(addrs) autorelease];
}


#pragma mark -
#pragma mark TRUST/POLICY STUFF:


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

+ (SecPolicyRef) X509Policy {
    static SecPolicyRef sX509Policy = NULL;
    if (!sX509Policy)
        sX509Policy = [self policyForOID: CSSMOID_APPLE_X509_BASIC];
    return sX509Policy;
}

+ (SecPolicyRef) SSLPolicy {
    static SecPolicyRef sSSLPolicy = NULL;
    if (!sSSLPolicy)
        sSSLPolicy = [self policyForOID: CSSMOID_APPLE_TP_SSL];
    return sSSLPolicy;
}

+ (SecPolicyRef) SMIMEPolicy {
    static SecPolicyRef sSMIMEPolicy = NULL;
    if (!sSMIMEPolicy)
        sSMIMEPolicy = [self policyForOID: CSSMOID_APPLE_TP_SMIME];
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
        

- (BOOL) setUserTrust: (SecTrustUserSetting)trustSetting
{
    if (trustSetting == kSecTrustResultProceed) {
        return check(SecTrustSettingsSetTrustSettings(_certificateRef, 
                                                      kSecTrustSettingsDomainUser, nil),
                     @"SecTrustSettingsSetTrustSettings");
    } else if (trustSetting == kSecTrustResultDeny) {
        OSStatus err = SecTrustSettingsRemoveTrustSettings(_certificateRef, 
                                                           kSecTrustSettingsDomainUser);
        return err == errSecItemNotFound || check(err, @"SecTrustSettingsRemoveTrustSettings");
    } else
        return paramErr;
}


@end


NSString* MYPolicyGetName( SecPolicyRef policy ) {
    if (!policy)
        return @"(null)";
    CSSM_OID oid = {};
    SecPolicyGetOID(policy, &oid);
    return $sprintf(@"SecPolicy[%@]", OIDAsString(oid));
}

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
    if (result>=0 && result <=kSecTrustResultOtherError)
        return kTrustResultNames[result];
    else
        return $sprintf(@"(Unknown trust result %i)", result);
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


#endif !MYCRYPTO_USE_IPHONE_API



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
