//
//  MYKey-iPhone.m
//  MYCrypto
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
    return [self initWithKeychainItemRef: (SecKeychainItemRef)key];
}


- (id) _initWithKeyData: (NSData*)data
            forKeychain: (SecKeychainRef)keychain
{
    NSMutableDictionary *info = $mdict({(__bridge id)kSecClass, (__bridge id)kSecClassKey},
                                        {(__bridge id)kSecAttrKeyType, (__bridge id)self.keyType},
                                        {(__bridge id)kSecValueData, data},
                                        {(__bridge id)kSecAttrIsPermanent, (keychain ?$true :$false)},
                                        {(__bridge id)kSecReturnPersistentRef, (keychain ?$true :$false)} );
    SecKeyRef key = (SecKeyRef)[MYKeychain _addItemWithInfo: info];
    if (!key) {
        return nil;
    }
    self = [self initWithKeyRef: (SecKeyRef)key];
    if (self) {
        if (!keychain)
            _keyData = [data copy];
        
        //TEMP For debugging:
        AssertEqual(self.keyData, data);
    }
    return self;
}

- (id) initWithKeyData: (NSData*)data {
    return [self _initWithKeyData: data forKeychain: nil];
}


/*- (NSData*) persistentRef {
    NSDictionary *info = $dict( {(id)kSecValueRef, (id)self.keyRef},
                              //{(id)kSecAttrIsPermanent, (self.isPersistent ?$true :$false)},
                                {(id)kSecReturnPersistentRef, $true} );
    CFDataRef data;
    if (!check(SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef*)&data), @"SecItemCopyMatching"))
        return nil;
    if (!data)
        Warn(@"MYKey persistentRef couldn't get ref");
    return [NSMakeCollectable(data) autorelease];
}*/


- (SecExternalItemType) keyClass {
    AssertAbstractMethod();
}

- (SecExternalItemType) keyType {
    return NULL;
}

- (NSData*) keyData {
    if (_keyData)
        return _keyData;
    
    NSDictionary *info = $dict( {(__bridge id)kSecValueRef, (__bridge id)self.keyRef},
                              //{(__bridge id)kSecAttrIsPermanent, (self.isPersistent ?$true :$false)},
                                {(__bridge id)kSecReturnData, $true} );
    CFDataRef data;
    if (!check(SecItemCopyMatching((__bridge CFDictionaryRef)info, (CFTypeRef*)&data), @"SecItemCopyMatching")) {
        Log(@"SecItemCopyMatching failed; input = %@", info);
        return nil;
    } else {
        Assert(data!=NULL);
        _keyData = (NSData*)CFBridgingRelease(data);
        return _keyData;
    }
    // The format of this data is not documented. There's been some reverse-engineering:
    // https://devforums.apple.com/message/32089#32089
    // Apparently it is a DER-formatted sequence of a modulus followed by an exponent.
    // This can be converted to OpenSSL format by wrapping it in some additional DER goop.
}

- (MYSHA1Digest*) _keyDigest {
    return [self.keyData my_SHA1Digest];
}

- (unsigned) keySizeInBits {
    return [[self _attribute: kSecAttrKeySizeInBits] intValue];
}

- (SecKeyRef) keyRef {
    return (SecKeyRef) self.keychainItemRef;
}


- (id) _attribute: (CFTypeRef)attribute {
    NSDictionary *info = $dict({(__bridge id)kSecValueRef, (__bridge id)self.keyRef},
            {(__bridge id)kSecAttrIsPermanent, (self.isPersistent ?$true :$false)},
                               {(__bridge id)kSecReturnAttributes, $true});
    CFDictionaryRef attrs = NULL;
    if (!check(SecItemCopyMatching((__bridge CFDictionaryRef)info, (CFTypeRef*)&attrs), @"SecItemCopyMatching"))
        return nil;
    CFTypeRef rawValue = CFDictionaryGetValue(attrs,attribute);
    id value = rawValue ?(id)CFBridgingRelease(CFRetain(rawValue)) :nil;
    CFRelease(attrs);
    return value;
}

- (BOOL) setValue: (NSString*)value ofAttribute: (MYKeychainAttrType)attribute {
    if (!value)
        value = (id)[NSNull null];
    NSDictionary *query = $dict( {(__bridge id)kSecValueRef, (__bridge id)self.keyRef} );
    NSDictionary *attrs = $dict( {(__bridge id)attribute, value} );
    return check(SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs), @"SecItemUpdate");
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
        Warn(@"%scrypting failed (%ld)", (operation ?"En" :"De"), err);
        // Note: One of the errors I've seen is -9809, which is errSSLCrypto (SecureTransport.h)
        return nil;
    } else
        return [NSData dataWithBytesNoCopy: outputBuf length: outputLength freeWhenDone: YES];
}


@end


#endif //MYCRYPTO_USE_IPHONE_API



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
