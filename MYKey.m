//
//  MYKey.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKey.h"
#import "MYCrypto_Private.h"
#import "MYDigest.h"
#import "MYErrorUtils.h"

#if !MYCRYPTO_USE_IPHONE_API


#pragma mark -
@implementation MYKey


- (id) initWithKeyRef: (SecKeyRef)key {
    return [super initWithKeychainItemRef: (SecKeychainItemRef)key];
}

- (id) _initWithKeyData: (NSData*)keyData
            forKeychain: (SecKeychainRef)keychain {
    Assert(keyData!=nil);
    SecKeyImportExportParameters params = {};
    SecKeyRef key = importKey(keyData, self.keyClass, keychain, &params);
    if (!key) {
        [self release];
        return nil;
    }
    self = [self initWithKeyRef: key];
    CFRelease(key);
    if (self) {
#if MYCRYPTO_USE_IPHONE_API
        if (!keychain)
            self.isPersistent = NO;
#endif
    }
    return self;
}

- (id) initWithKeyData: (NSData*)data {
    return [self _initWithKeyData: data forKeychain: nil];
}


- (NSString*) description {
    return $sprintf(@"%@[%@ /%p]", [self class], (self.name ?:@""), self.keychainItemRef);
}

- (SecExternalItemType) keyClass {
    AssertAbstractMethod();
}

#if MYCRYPTO_USE_IPHONE_API
- (SecExternalItemType) keyType {
    return NULL;
}
#endif

- (SecKeyRef) keyRef {
    return (SecKeyRef) self.keychainItemRef;
}

- (const CSSM_KEY*) cssmKey {
    const CSSM_KEY *cssmKey = NULL;
    Assert(check(SecKeyGetCSSMKey(self.keyRef, &cssmKey), @"SecKeyGetCSSMKey"), 
           @"Failed to get CSSM_KEY");
    return cssmKey;
}

- (const CSSM_CSP_HANDLE) cssmCSPHandle {
    CSSM_CSP_HANDLE cspHandle = 0;
    Assert(check(SecKeyGetCSPHandle(self.keyRef, &cspHandle), @"SecKeyGetCSPHandle"),
           @"Failed to get CSSM_CSP_HANDLE");
    return cspHandle;
}

- (CSSM_ALGORITHMS) cssmAlgorithm {
    return self.cssmKey->KeyHeader.AlgorithmId;
}

- (const CSSM_ACCESS_CREDENTIALS*) cssmCredentialsForOperation: (CSSM_ACL_AUTHORIZATION_TAG)operation
                                                          type: (SecCredentialType)type
                                                         error: (NSError**)outError
{
    const CSSM_ACCESS_CREDENTIALS *credentials = NULL;
    OSStatus err = SecKeyGetCredentials(self.keyRef,
                                        operation,
                                        type,
                                        &credentials);
    if (!MYReturnError(outError, err,NSOSStatusErrorDomain, @"Couldn't get credentials for key"))
        return NULL;
    return credentials;
}

- (SecExternalFormat) _externalFormat {
    return kSecFormatRawKey;
}

- (NSData*) keyData {
    CFDataRef data = NULL;
    if (check(SecKeychainItemExport(self.keyRef, self._externalFormat, 0, NULL, &data),
              @"SecKeychainItemExport"))
        return [(id)CFMakeCollectable(data) autorelease];
    else
        return nil;
}

- (unsigned) keySizeInBits {
    const CSSM_KEY *key = self.cssmKey;
    Assert(key);
    return key->KeyHeader.LogicalKeySizeInBits;
}

- (NSString*) name {
    return [self stringValueOfAttribute: kSecKeyPrintName];
}

- (void) setName: (NSString*)name {
    [self setValue: name ofAttribute: kSecKeyPrintName];
}

- (NSString*) comment {
    return [self stringValueOfAttribute: kSecKeyApplicationTag];
}

- (void) setComment: (NSString*)comment {
    [self setValue: comment ofAttribute: kSecKeyApplicationTag];
}

- (NSString*) alias {
    return [self stringValueOfAttribute: kSecKeyAlias];
}

- (void) setAlias: (NSString*)alias {
    [self setValue: alias ofAttribute: kSecKeyAlias];
}


#pragma mark -
#pragma mark UTILITY FUNCTIONS:


SecKeyRef importKey(NSData *data, 
                    SecExternalItemType type,
                    SecKeychainRef keychain,
                    SecKeyImportExportParameters *params) {
    SecExternalFormat inputFormat = (type==kSecItemTypeSessionKey) ?kSecFormatRawKey :kSecFormatUnknown;
    CFArrayRef items = NULL;
    
    params->version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params->flags |= kSecKeyImportOnlyOne;
    params->keyAttributes |= CSSM_KEYATTR_EXTRACTABLE;
    if (keychain) {
        params->keyAttributes |= CSSM_KEYATTR_PERMANENT;
        if (type==kSecItemTypeSessionKey)
            params->keyUsage = CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_DECRYPT;
        else if (type==kSecItemTypePublicKey)
            params->keyUsage = CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_VERIFY | CSSM_KEYUSE_WRAP;
        else if (type==kSecItemTypePrivateKey)
            params->keyUsage = CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_SIGN;
    }
    if (!check(SecKeychainItemImport((CFDataRef)data, NULL, &inputFormat, &type,
                                     0, params, keychain, &items),
               @"SecKeychainItemImport"))
        return nil;
    if (!items || CFArrayGetCount(items) != 1)
        return nil;
    SecKeyRef key = (SecKeyRef)CFRetain(CFArrayGetValueAtIndex(items,0));
    CFRelease(items);
    return key; // caller must CFRelease
}


- (MYSHA1Digest*) _keyDigest {
    MYSHA1Digest *digest = nil;
    CSSM_DATA *keyDigest = NULL;
    CSSM_CC_HANDLE context = [self _createPassThroughContext];
    if (context) {
        if (checkcssm(CSSM_CSP_PassThrough(context, CSSM_APPLECSP_KEYDIGEST, NULL, (void**)&keyDigest),
                      @"CSSM_CSP_PassThrough")) {
            if (keyDigest && keyDigest->Data) {
                digest = [[[MYSHA1Digest alloc] initWithRawDigest: keyDigest->Data
                                                           length: keyDigest->Length] autorelease];
            }
        } else {
            SecKeyRef keyRef = self.keyRef;
            // Note - CSSM_CSP_PassThrough fails on a couple of private keys I've seen; it seems to
            // be ones that are either expired or don't have a matching public key at all (?)
            Warn(@"Failed to get digest of SecKeyRef %p (name='%@' appTag='%@')", 
                 keyRef,
                 self.name,
                 self.comment);
            NSData *digestData = [[self class] _getAttribute: kSecKeyLabel 
                                                      ofItem: (SecKeychainItemRef)keyRef];
            if (digestData) {
                digest = (MYSHA1Digest*) [MYSHA1Digest digestFromDigestData: digestData];
                if (!digest)
                    Warn(@"Digest property of key %p was invalid SHA-1: %@", keyRef,digestData);
            }
        }
        CSSM_DeleteContext(context);
    }
    return digest;
}


/** Asymmetric encryption/decryption; used by MYPublicKey and MYPrivateKey. */
- (NSData*) _crypt: (NSData*)data operation: (BOOL)operation {
    CAssert(data);
    const CSSM_ACCESS_CREDENTIALS *credentials;
    credentials = [self cssmCredentialsForOperation: (operation ?CSSM_ACL_AUTHORIZATION_ENCRYPT 
                                                                :CSSM_ACL_AUTHORIZATION_DECRYPT) 
                                               type: kSecCredentialTypeDefault
                                              error: nil];
    if (!credentials)
        return nil;
    
    CSSM_CC_HANDLE ccHandle;
    if (!checkcssm(CSSM_CSP_CreateAsymmetricContext(self.cssmCSPHandle,
                                                    CSSM_ALGID_RSA,
                                                    credentials,
                                                    self.cssmKey,
                                                    CSSM_PADDING_PKCS1,
                                                    &ccHandle),
                   @"CSSM_CSP_CreateAsymmetricContext"))
        return nil;
    
    CSSM_DATA original = {data.length, (void*)data.bytes};
    CSSM_DATA result = {};
    size_t outputLength;
    BOOL ok;
    if (operation)
        ok = checkcssm(CSSM_EncryptData(ccHandle, &original, 1, &result, 1, &outputLength, &result),
                       @"CSSM_EncryptData");
    else
        ok = checkcssm(CSSM_DecryptData(ccHandle, &original, 1, &result, 1, &outputLength, &result),
                       @"CSSM_DecryptData");
    CSSM_DeleteContext(ccHandle);
    return ok ?[NSData dataWithBytesNoCopy: result.Data length: outputLength freeWhenDone: YES] :nil;
}


- (CSSM_CC_HANDLE) _createSignatureContext: (CSSM_ALGORITHMS)algorithm {
    const CSSM_ACCESS_CREDENTIALS *credentials;
    credentials = [self cssmCredentialsForOperation: CSSM_ACL_AUTHORIZATION_SIGN 
                                               type: kSecCredentialTypeDefault
                                              error: nil];
    if (credentials) {
        CSSM_CC_HANDLE ccHandle = 0;
        if (checkcssm(CSSM_CSP_CreateSignatureContext(self.cssmCSPHandle, 
                                                      algorithm, 
                                                      credentials,
                                                      self.cssmKey,
                                                      &ccHandle),
                             @"CSSM_CSP_CreateSignatureContext") )
            return ccHandle;
    }
    return 0;
}

- (CSSM_CC_HANDLE) _createPassThroughContext
{
    CSSM_CC_HANDLE ccHandle = 0;
    if (checkcssm(CSSM_CSP_CreatePassThroughContext(self.cssmCSPHandle, self.cssmKey, &ccHandle), 
                          @"CSSM_CSP_CreatePassThroughContext") )
        return ccHandle;
    else
        return 0;
}


@end

#endif MYCRYPTO_USE_IPHONE_API



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
