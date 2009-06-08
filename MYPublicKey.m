//
//  MYPublicKey.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYPublicKey.h"
#import "MYCrypto_Private.h"
#import "MYDigest.h"
#import "MYASN1Object.h"
#import "MYDEREncoder.h"
#import "MYBERParser.h"
#import "MYErrorUtils.h"
#import <CommonCrypto/CommonDigest.h>


#pragma mark -
@implementation MYPublicKey


- (id) initWithModulus: (NSData*)modulus exponent: (unsigned)exponent {
    // An RSA key is encoded in ASN.1 as a sequence of modulus and exponent, both as integers.
    MYASN1BigInteger *modulusInt = [[MYASN1BigInteger alloc] initWithUnsignedData: modulus];
    id asn1 = $array( modulusInt, $object(exponent) );
    [modulusInt release];
    NSData *keyData = [MYDEREncoder encodeRootObject: asn1 error: nil];
    return [self initWithKeyData: keyData];
}


- (void) dealloc
{
    [_digest release];
    [super dealloc];
}

- (SecExternalItemType) keyClass {
#if MYCRYPTO_USE_IPHONE_API
    return kSecAttrKeyClassPublic;
#else
    return kSecItemTypePublicKey;
#endif
}

#if MYCRYPTO_USE_IPHONE_API
- (SecExternalItemType) keyType {
    return kSecAttrKeyTypeRSA;
}

- (MYSHA1Digest*) _keyDigest {
    return (MYSHA1Digest*) [MYSHA1Digest digestFromDigestData: [self _attribute: kSecAttrApplicationLabel]];
}
#endif

- (NSUInteger)hash {
    return self.publicKeyDigest.hash;
}

- (NSString*) description {
    return $sprintf(@"%@[%@]", [self class], self.publicKeyDigest.abbreviatedHexString);
}

- (MYSHA1Digest*) publicKeyDigest {
    if (!_digest)
        _digest = [[self _keyDigest] retain];
    return _digest;
}

#if !MYCRYPTO_USE_IPHONE_API
- (SecExternalFormat) _externalFormat {
    return kSecFormatBSAFE;
}
#endif


- (BOOL) getModulus: (NSData**)outModulus exponent: (unsigned*)outExponent {
    Assert(outModulus!=nil);
    Assert(outExponent!=nil);
    NSArray *asn1 = $castIf(NSArray, MYBERParse(self.keyData, nil));
    if (!asn1 || asn1.count != 2)
        return NO;
    *outModulus = $castIf(MYASN1BigInteger, [asn1 objectAtIndex: 0]).unsignedData;
    *outExponent = $castIf(NSNumber, [asn1 objectAtIndex: 1]).unsignedIntValue;
    return (*outModulus!=nil && *outExponent>=3);
}


- (NSData*) rawEncryptData: (NSData*)data {
    return [self _crypt: data operation: YES];
}


- (BOOL) verifySignature: (NSData*)signature ofData: (NSData*)data {
    Assert(data);
    Assert(signature);
    
#if MYCRYPTO_USE_IPHONE_API
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes,data.length, digest);
    OSStatus err = SecKeyRawVerify(self.keyRef, kSecPaddingPKCS1SHA1,
                                   digest,sizeof(digest), //data.bytes, data.length,
                                   signature.bytes, signature.length);
    return err==noErr;
    
#else
    CSSM_CC_HANDLE ccHandle = [self _createSignatureContext: CSSM_ALGID_SHA1WithRSA];
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
#endif
}


#if !TARGET_OS_IPHONE
- (CSSM_WRAP_KEY*) _unwrappedCSSMKey {
    const CSSM_KEY *key = self.cssmKey;
    
    if (key->KeyHeader.BlobType == CSSM_KEYBLOB_WRAPPED) {
        Warn(@"Key is already wrapped.\n");
        return NULL;
    }
    
    if (key->KeyHeader.KeyClass != CSSM_KEYCLASS_PUBLIC_KEY)
        Warn(@"Warning: Null wrapping a non-public key - this is a dangerous operation.\n");
    
    const CSSM_ACCESS_CREDENTIALS* credentials;
    credentials = [self cssmCredentialsForOperation: CSSM_ACL_AUTHORIZATION_EXPORT_WRAPPED
                                               type: kSecCredentialTypeDefault error: nil];
    CSSM_CC_HANDLE ccHandle;
    if (!checkcssm(CSSM_CSP_CreateSymmetricContext(self.cssmCSPHandle, 
                                                   CSSM_ALGID_NONE, CSSM_ALGMODE_WRAP, 
                                                   NULL, NULL, NULL, 
                                                   CSSM_PADDING_NONE, NULL, 
                                                   &ccHandle),
                   @"CSSM_CSP_CreateSymmetricContext"))
        return NULL;
                   
    CSSM_WRAP_KEY *result = malloc(sizeof(CSSM_WRAP_KEY));
    if (!checkcssm(CSSM_WrapKey(ccHandle, credentials, key, NULL, result),
                      @"CSSM_WrapKey")) {
        free(result);
        result = NULL;
    }
    CSSM_DeleteContext(ccHandle);
    return result;
}


- (NSData*) wrapSessionKey: (MYSymmetricKey*)sessionKey {
    const CSSM_ACCESS_CREDENTIALS* credentials;
    credentials = [self cssmCredentialsForOperation: CSSM_ACL_AUTHORIZATION_EXPORT_WRAPPED
                                               type: kSecCredentialTypeDefault error: nil];
    CSSM_CSP_HANDLE cspHandle = self.cssmCSPHandle;
    CSSM_CC_HANDLE ctx;
    if (!checkcssm(CSSM_CSP_CreateAsymmetricContext(cspHandle,
                                                    self.cssmAlgorithm,
                                                    credentials, 
                                                    self.cssmKey,
                                                    CSSM_PADDING_PKCS1,
                                                    &ctx), 
                   @"CSSM_CSP_CreateAsymmetricContext"))
        return nil;
        
    // Now wrap the key:
    NSData *result = nil;
    CSSM_WRAP_KEY wrappedKey = {};
    CSSM_DATA descriptiveData = {};
    if (checkcssm(CSSM_WrapKey(ctx, credentials, sessionKey.cssmKey, &descriptiveData, &wrappedKey),
                  @"CSSM_WrapKey")) {
        // ...and copy the wrapped key data to the result NSData:
        result = [NSData dataWithBytes: wrappedKey.KeyData.Data length: wrappedKey.KeyData.Length];
        CSSM_FreeKey(cspHandle, credentials, &wrappedKey, NO);
    }
    // Finally, delete the context
    CSSM_DeleteContext(ctx);
    return result;
}


#endif


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
