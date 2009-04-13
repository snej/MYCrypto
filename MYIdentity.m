//
//  MYIdentity.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/9/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYIdentity.h"
#import "MYCrypto_Private.h"


@implementation MYIdentity


/** Creates a MYIdentity object for an existing Keychain identity reference. */
+ (MYIdentity*) identityWithIdentityRef: (SecIdentityRef)identityRef {
    return [[[self alloc] initWithIdentityRef: identityRef] autorelease];
}

- (id) initWithIdentityRef: (SecIdentityRef)identityRef {
    Assert(identityRef);
    SecCertificateRef certificateRef;
    if (!check(SecIdentityCopyCertificate(identityRef, &certificateRef), @"SecIdentityCopyCertificate")) {
        [self release];
        return nil;
    }
    self = [super initWithCertificateRef: certificateRef];
    if (self) {
        _identityRef = identityRef;
        CFRetain(identityRef);
    }
    CFRelease(certificateRef);
    return self;
}


#if !TARGET_OS_IPHONE
- (id) initWithCertificateRef: (SecCertificateRef)certificateRef {
    self = [super initWithCertificateRef: certificateRef];
    if (self) {
        if (!check(SecIdentityCreateWithCertificate(NULL, certificateRef, &_identityRef),
                   @"SecIdentityCreateWithCertificate")) {
            [self release];
            return nil;
        }
    }
    return self;
}
#endif

- (void) dealloc
{
    if (_identityRef) CFRelease(_identityRef);
    [super dealloc];
}

- (void) finalize
{
    if (_identityRef) CFRelease(_identityRef);
    [super finalize];
}


@synthesize identityRef=_identityRef;

- (MYPrivateKey*) privateKey {
    SecKeyRef keyRef = NULL;
    if (!check(SecIdentityCopyPrivateKey(_identityRef, &keyRef), @"SecIdentityCopyPrivateKey"))
        return NULL;
    MYPrivateKey *privateKey = [[MYPrivateKey alloc] _initWithKeyRef: keyRef
                                                          publicKey: self.publicKey];
    CFRelease(keyRef);
    return [privateKey autorelease];
}


#if !TARGET_OS_IPHONE

+ (MYIdentity*) preferredIdentityForName: (NSString*)name
{
    Assert(name);
    SecIdentityRef identityRef;
    OSStatus err = SecIdentityCopyPreference((CFStringRef)name, 0, NULL, &identityRef);
    if (err==errKCItemNotFound || !check(err,@"SecIdentityCopyPreference") || !identityRef)
        return nil;
    return [self identityWithIdentityRef: identityRef];
}

- (BOOL) makePreferredIdentityForName: (NSString*)name {
    Assert(name);
    return check(SecIdentitySetPreference(_identityRef, (CFStringRef)name, 0),
                 @"SecIdentitySetPreference");
}

#endif !TARGET_OS_IPHONE

@end
