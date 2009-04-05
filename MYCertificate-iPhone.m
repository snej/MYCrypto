//
//  MYCertificate-iPhone.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCertificate.h"
#import "MYCrypto_Private.h"

#if USE_IPHONE_API


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
{
    SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, (CFDataRef)data);
    self = [self initWithCertificateRef: certificateRef];
    CFRelease(certificateRef);
    return self;
}


@synthesize certificateRef=_certificateRef;

- (NSData*) certificateData {
    CFDataRef data = SecCertificateCopyData(_certificateRef);
    return data ?[(id)CFMakeCollectable(data) autorelease] :nil;
}

- (MYPublicKey*) publicKey {
    SecTrustRef trust = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    OSStatus err = SecTrustCreateWithCertificates((CFArrayRef)$array((id)_certificateRef),
                                                  policy,
                                                  &trust);
    CFRelease(policy);
    if (!check(err,@"SecTrustCreateWithCertificates"))
        return nil;
    
    MYPublicKey *key = nil;
    SecKeyRef keyRef = SecTrustCopyPublicKey(trust);
    if (keyRef) {
        key = [[[MYPublicKey alloc] initWithKeyRef: keyRef] autorelease];
        CFRelease(keyRef);
    }
    CFRelease(trust);
    return key;
}


- (NSString*) commonName {
    CFStringRef name = SecCertificateCopySubjectSummary(_certificateRef);
    return name ?[(id)CFMakeCollectable(name) autorelease] :nil;
}

- (NSArray*) emailAddresses {
    return nil; //FIX UNIMPLEMENTED
}


@end

#endif USE_IPHONE_API
