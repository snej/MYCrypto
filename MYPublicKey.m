//
//  MYPublicKey.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYPublicKey.h"
#import "MYCrypto_Private.h"

#if !USE_IPHONE_API

#import "MYDigest.h"
#import "MYErrorUtils.h"
#import <CommonCrypto/CommonDigest.h>


static CSSM_CC_HANDLE cssmCreatePassThroughContext(SecKeyRef key);


#pragma mark -
@implementation MYPublicKey


- (void) dealloc
{
    [_digest release];
    [super dealloc];
}

- (SecExternalItemType) keyType {
    return kSecItemTypePublicKey;
}
- (NSUInteger)hash {
    return self.publicKeyDigest.hash;
}

- (NSString*) description {
    return $sprintf(@"%@[%@]", [self class], self.publicKeyDigest.abbreviatedHexString);
}

- (MYPublicKey*) asPublicKey {
    return self;
}


+ (MYSHA1Digest*) _digestOfKey: (SecKeyRef)key {
    Assert(key);
    MYSHA1Digest *digest = nil;
    CSSM_DATA *keyDigest = NULL;
    CSSM_CC_HANDLE context = cssmCreatePassThroughContext(key);
    if (context) {
        if (checkcssm(CSSM_CSP_PassThrough(context, CSSM_APPLECSP_KEYDIGEST, NULL, (void**)&keyDigest),
                      @"CSSM_CSP_PassThrough")) {
            if (keyDigest && keyDigest->Data) {
                digest = [[[MYSHA1Digest alloc] initWithRawDigest: keyDigest->Data
                                                           length: keyDigest->Length] autorelease];
            }
        } else {
            // Note - CSSM_CSP_PassThrough fails on a couple of private keys I've seen; it seems to
            // be ones that are either expired or don't have a matching public key at all (?)
            Warn(@"Failed to get digest of SecKeyRef %p (name='%@' appTag='%@')", key,
                 [self _getStringAttribute: kSecKeyPrintName ofItem: (SecKeychainItemRef)key],
                 [self _getStringAttribute: kSecKeyApplicationTag ofItem: (SecKeychainItemRef)key]);
            NSData *digestData = [self _getAttribute: kSecKeyLabel ofItem: (SecKeychainItemRef)key];
            if (digestData) {
                digest = (MYSHA1Digest*) [MYSHA1Digest digestFromDigestData: digestData];
                if (!digest)
                    Warn(@"Digest property of key %p was invalid SHA-1: %@", key,digestData);
            }
        }
        CSSM_DeleteContext(context);
    }
    return digest;
}

- (MYSHA1Digest*) publicKeyDigest {
    if (!_digest)
        _digest = [[[self class] _digestOfKey: self.keyRef] retain];
    return _digest;
}

- (NSData*) keyData {
    return [self exportKeyInFormat: kSecFormatOpenSSL withPEM: NO];
}


- (NSData*) encryptData: (NSData*)data {
    return _crypt(self.keyRef,data,kCCEncrypt);
}


- (BOOL) verifySignature: (NSData*)signature ofData: (NSData*)data {
    Assert(data);
    Assert(signature);
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes,data.length, digest);
    
    CSSM_CC_HANDLE ccHandle = cssmCreateSignatureContext(self.keyRef);
    if (!ccHandle) return NO;
    CSSM_DATA original = {data.length, (void*)data.bytes};
    CSSM_DATA sig = {signature.length, (void*)signature.bytes};
    CSSM_RETURN cssmErr = CSSM_VerifyData(ccHandle, &original, 1, CSSM_ALGID_NONE, &sig);
    CSSM_DeleteContext(ccHandle);
    if (cssmErr == CSSM_OK)
        return YES;
    if (cssmErr != CSSMERR_CSP_VERIFY_FAILED)
        Warn(@"CSSM error verifying signature: %u", MYErrorName(MYCSSMErrorDomain,cssmErr));
    return NO;
}


@end




#pragma mark -
#pragma mark UTILITY FUNCTIONS:


NSData* _crypt(SecKeyRef key, NSData *data, CCOperation op) {
    CAssert(data);
    const CSSM_KEY* cssmKey;
    const CSSM_ACCESS_CREDENTIALS *credentials;
    CSSM_CSP_HANDLE cspHandle;
    CSSM_CC_HANDLE ccHandle;
    if (!check(SecKeyGetCSSMKey(key, &cssmKey), @"GetCSSMKey")
            || !check(SecKeyGetCredentials(key, CSSM_ACL_AUTHORIZATION_SIGN, kSecCredentialTypeWithUI,
                                           &credentials), @"GetCredentials")
            || !check(SecKeyGetCSPHandle(key, &cspHandle), @"GetCSPHandle")
        
            || !checkcssm(CSSM_CSP_CreateAsymmetricContext(cspHandle, CSSM_ALGID_RSA,
                                                               credentials, cssmKey,
                                                               CSSM_PADDING_PKCS1, &ccHandle),
                          @"CSSM_CSP_CreateAsymmetricContext"))
        return nil;
    
    CSSM_DATA original = {data.length, (void*)data.bytes};
    CSSM_DATA result = {};
    size_t outputLength;
    BOOL ok;
    if (op==kCCEncrypt)
        ok = checkcssm(CSSM_EncryptData(ccHandle, &original, 1, &result, 1, &outputLength, &result),
                       @"CSSM_EncryptData");
    else
        ok = checkcssm(CSSM_DecryptData(ccHandle, &original, 1, &result, 1, &outputLength, &result),
                       @"CSSM_DecryptData");
    CSSM_DeleteContext(ccHandle);
    return ok ?[NSData dataWithBytesNoCopy: result.Data length: outputLength freeWhenDone: YES] :nil;
}


CSSM_CC_HANDLE cssmCreateSignatureContext(SecKeyRef key) 
{
    const CSSM_KEY* cssmKey;
    const CSSM_ACCESS_CREDENTIALS *credentials;
    CSSM_CSP_HANDLE cspHandle;
    CSSM_CC_HANDLE ccHandle;
    if (check(SecKeyGetCSSMKey(key, &cssmKey), @"GetCSSMKey")
            && check(SecKeyGetCredentials(key, CSSM_ACL_AUTHORIZATION_SIGN, kSecCredentialTypeWithUI,
                               &credentials), @"GetCredentials")
            && check(SecKeyGetCSPHandle(key, &cspHandle), @"GetCSPHandle")
            && checkcssm(CSSM_CSP_CreateSignatureContext(cspHandle, CSSM_ALGID_SHA1WithRSA, 
                                                          credentials,
                                                          cssmKey, &ccHandle),
                         @"CSSM_CSP_CreateSignatureContext") )
        return ccHandle;
    else
        return 0;
}

static CSSM_CC_HANDLE cssmCreatePassThroughContext(SecKeyRef key) 
{
    const CSSM_KEY* cssmKey;
    CSSM_CSP_HANDLE cspHandle;
    CSSM_CC_HANDLE ccHandle;
    if (check(SecKeyGetCSSMKey(key, &cssmKey), @"GetCSSMKey")
            && check(SecKeyGetCSPHandle(key, &cspHandle), @"GetCSPHandle")
            && checkcssm(CSSM_CSP_CreatePassThroughContext(cspHandle, cssmKey, &ccHandle), 
                          @"CSSM_CSP_CreatePassThroughContext") )
        return ccHandle;
    else
        return 0;
}

#endif !USE_IPHONE_API



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
