//
//  MYIdentity.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/9/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYIdentity.h"
#import "MYCrypto_Private.h"
#import "MYDigest.h"


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


- (id) initWithCertificateRef: (SecCertificateRef)certificateRef {
    self = [super initWithCertificateRef: certificateRef];
    if (self) {
#if !MYCRYPTO_USE_IPHONE_API
        if (!check(SecIdentityCreateWithCertificate(NULL, certificateRef, &_identityRef),
                   @"SecIdentityCreateWithCertificate")) {
            [self release];
            return nil;
        }
#else
        MYSHA1Digest *keyDigest = self.publicKey.publicKeyDigest;
        if (!keyDigest) {
            Warn(@"MYIdentity: Couldn't get key digest of cert %@",certificateRef);
            [self release];
            return nil;
        }
        _identityRef = [self.keychain identityWithDigest: keyDigest].identityRef;
        if (!_identityRef) {
            Warn(@"MYIdentity: Couldn't look up identity for cert %@ with %@",certificateRef, keyDigest);
            [self release];
            return nil;
        }
        
        // Debugging: Make sure the cert is correct
        SecCertificateRef identitysCert = NULL;
        SecIdentityCopyCertificate(_identityRef, &identitysCert);
        CFDataRef identitysData = SecCertificateCopyData(identitysCert);
        AssertEqual(self.certificateData, (NSData*)identitysData);
        CFRelease(identitysData);
        CFRelease(identitysCert);
        
        CFRetain(_identityRef);
#endif
    }
    return self;
}

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


- (BOOL) removeFromKeychain {
    return [self.privateKey removeFromKeychain] && [super removeFromKeychain];
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
