//
//  MYKey-iPhone.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 4/4/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//


#import "MYCrypto_Private.h"

#if MYCRYPTO_USE_IPHONE_API

#import "MYDigest.h"
#import "MYErrorUtils.h"


#pragma mark -
@implementation MYKey


- (id) initWithKeyRef: (SecKeyRef)key {
    return [super initWithKeychainItemRef: (SecKeychainItemRef)key];
}


- (id) _initWithKeyData: (NSData*)data
            forKeychain: (SecKeychainRef)keychain
{
    NSDictionary *info = $dict( {(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)self.keyType},
                                {(id)kSecValueData, data},
                                {(id)kSecAttrIsPermanent, $object(keychain!=nil)},
                                {(id)kSecReturnRef, $true} );
    SecKeyRef key;
    if (!check(SecItemAdd((CFDictionaryRef)info, (CFTypeRef*)&key), @"SecItemAdd"))
        return nil;
    else
        return [self initWithKeyRef: (SecKeyRef)key];
}

- (id) initWithKeyData: (NSData*)data {
    return [self _initWithKeyData: data forKeychain: nil];
}


- (SecExternalItemType) keyType {
    AssertAbstractMethod();
}


- (NSData*) keyData {
    NSDictionary *info = $dict( {(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)self.keyType},
                                {(id)kSecMatchItemList, $array((id)self.keyRef)},
                                {(id)kSecReturnData, $true} );
    CFDataRef data;
    if (!check(SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef*)&data), @"SecItemCopyMatching"))
        return nil;
    else
        return [(id)CFMakeCollectable(data) autorelease];
}


- (SecKeyRef) keyRef {
    return (SecKeyRef) self.keychainItemRef;
}


- (id) _attribute: (CFTypeRef)attribute {
    NSDictionary *info = $dict( {(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)self.keyType},
                                {(id)kSecMatchItemList, $array((id)self.keyRef)},
                                {(id)kSecReturnAttributes, $true} );
    CFDictionaryRef attrs = NULL;
    if (!check(SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef*)&attrs), @"SecItemCopyMatching"))
        return nil;
    CFTypeRef rawValue = CFDictionaryGetValue(attrs,attribute);
    id value = rawValue ?[[(id)CFMakeCollectable(rawValue) retain] autorelease] :nil;
    CFRelease(attrs);
    return value;
}

- (BOOL) setValue: (NSString*)value ofAttribute: (SecKeychainAttrType)attribute {
    if (!value)
        value = (id)[NSNull null];
    NSDictionary *query = $dict( {(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)self.keyType},
                                {(id)kSecMatchItemList, self._itemList} );
    NSDictionary *attrs = $dict( {(id)attribute, value} );
    return check(SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)attrs), @"SecItemUpdate");
}


- (NSString*) name {
    return [self _attribute: kSecAttrLabel];
}

- (void) setName: (NSString*)name {
    [self setValue: name ofAttribute: kSecAttrLabel];
}

- (NSString*) alias {
    return [self _attribute: kSecAttrApplicationTag];
}

- (void) setAlias: (NSString*)alias {
    [self setValue: alias ofAttribute: kSecAttrApplicationTag];
}




/** Asymmetric encryption/decryption; used by MYPublicKey and MYPrivateKey. */
- (NSData*) _crypt: (NSData*)data operation: (BOOL)operation {
    CAssert(data);
    size_t dataLength = data.length;
    SecKeyRef key = self.keyRef;
    size_t outputLength = MAX(dataLength, SecKeyGetBlockSize(key));
    void *outputBuf = malloc(outputLength);
    if (!outputBuf) return nil;
    OSStatus err;
    if (operation)
        err = SecKeyEncrypt(key, kSecPaddingNone,//PKCS1, 
                            data.bytes, dataLength,
                            outputBuf, &outputLength);
    else
        err = SecKeyDecrypt(key, kSecPaddingNone,//PKCS1, 
                            data.bytes, dataLength,
                            outputBuf, &outputLength);
    if (err) {
        free(outputBuf);
        Warn(@"%scrypting failed (%i)", (operation ?"En" :"De"), err);
        // Note: One of the errors I've seen is -9809, which is errSSLCrypto (SecureTransport.h)
        return nil;
    } else
        return [NSData dataWithBytesNoCopy: outputBuf length: outputLength freeWhenDone: YES];
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
