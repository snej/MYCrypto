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

- (id) _initWithKeyData: (NSData*)data
            forKeychain: (SecKeychainRef)keychain {
    SecKeyImportExportParameters params = {};
    SecKeyRef key = importKey(data, self.keyType, keychain, &params);
    if (!key) {
        [self release];
        return nil;
    }
    self = [self initWithKeyRef: key];
    CFRelease(key);
    return self;
}

- (id) initWithKeyData: (NSData*)data {
    return [self _initWithKeyData: data forKeychain: nil];
}


- (SecExternalItemType) keyType {
    AssertAbstractMethod();
}


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

- (NSData*) exportKeyInFormat: (SecExternalFormat)format withPEM: (BOOL)withPEM {
    CFDataRef data = NULL;
    if (check(SecKeychainItemExport(self.keyRef, format, (withPEM ?kSecItemPemArmour :0), NULL, &data),
              @"SecKeychainItemExport"))
        return [(id)CFMakeCollectable(data) autorelease];
    else
        return nil;
}

- (NSData*) keyData {
    return [self exportKeyInFormat: kSecFormatRawKey withPEM: NO];
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


@end




#pragma mark -
#pragma mark UTILITY FUNCTIONS:


SecKeyRef importKey(NSData *data, 
                    SecExternalItemType type,
                    SecKeychainRef keychain,
                    SecKeyImportExportParameters *params) {
    SecExternalFormat inputFormat = (type==kSecItemTypeSessionKey) ?kSecFormatRawKey :kSecFormatOpenSSL;
    CFArrayRef items = NULL;
    
    params->version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params->flags |= kSecKeyImportOnlyOne;
    params->keyAttributes |= CSSM_KEYATTR_EXTRACTABLE;
    if (keychain) {
        params->keyAttributes |= CSSM_KEYATTR_PERMANENT;
        if (type==kSecItemTypeSessionKey)
            params->keyUsage = CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_DECRYPT;
        else if (type==kSecItemTypePublicKey)
            params->keyUsage = CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_VERIFY;
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
