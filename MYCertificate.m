//
//  MYCertificate.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/26/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCertificate.h"
#import "MYCrypto_Private.h"

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


@end


#endif !MYCRYPTO_USE_IPHONE_API
