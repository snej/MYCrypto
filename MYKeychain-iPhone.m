//
//  MYKeychain-iPhone.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/31/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCrypto_Private.h"
#import "MYDigest.h"
#import "MYIdentity.h"


#if MYCRYPTO_USE_IPHONE_API


// from cssmtype.h:
enum {
    CSSM_CERT_UNKNOWN =					0x00,
    CSSM_CERT_X_509v1 =					0x01,
    CSSM_CERT_X_509v2 =					0x02,
    CSSM_CERT_X_509v3 =					0x03,

    CSSM_CERT_ENCODING_UNKNOWN =		0x00,
    CSSM_CERT_ENCODING_CUSTOM =			0x01,
    CSSM_CERT_ENCODING_BER =			0x02,
    CSSM_CERT_ENCODING_DER =			0x03,
};


@interface MYKeyEnumerator : NSEnumerator
{
    CFArrayRef _results;
    CFTypeRef _itemClass;
    CFIndex _index;
    MYKeychainItem *_currentObject;
}

- (id) initWithQuery: (NSMutableDictionary*)query;
+ (id) firstItemWithQuery: (NSMutableDictionary*)query;
@end



@implementation MYKeychain


+ (MYKeychain*) allKeychains
{
    // iPhone only has a single keychain.
    return [self defaultKeychain];
}

+ (MYKeychain*) defaultKeychain
{
    static MYKeychain *sDefaultKeychain;
    @synchronized(self) {
        if (!sDefaultKeychain) {
            sDefaultKeychain = [[self alloc] init];
        }
    }
    return sDefaultKeychain;
}


- (id) copyWithZone: (NSZone*)zone {
    // It's not necessary to make copies of Keychain objects. This makes it more efficient
    // to use instances as NSDictionary keys or store them in NSSets.
    return [self retain];
}



#pragma mark -
#pragma mark SEARCHING:


- (MYPublicKey*) publicKeyWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [MYKeyEnumerator firstItemWithQuery:
                $mdict({(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPublic},
                       {(id)kSecAttrApplicationLabel, pubKeyDigest.asData})];
}   

- (NSEnumerator*) enumeratePublicKeys {
    NSMutableDictionary *query = $mdict({(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPublic});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}


- (MYPrivateKey*) privateKeyWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [MYKeyEnumerator firstItemWithQuery:
                $mdict({(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPrivate},
                       {(id)kSecAttrApplicationLabel, pubKeyDigest.asData})];
}

- (NSEnumerator*) enumeratePrivateKeys {
    NSMutableDictionary *query = $mdict({(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPrivate});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (MYCertificate*) certificateWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [MYKeyEnumerator firstItemWithQuery:
                $mdict({(id)kSecClass, (id)kSecClassCertificate},
                       {(id)kSecAttrPublicKeyHash, pubKeyDigest.asData})];
}

- (NSEnumerator*) enumerateCertificates {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassCertificate});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (NSEnumerator*) enumerateCertificatesWithDigest: (MYSHA1Digest*)pubKeyDigest {
    NSMutableDictionary* query = $mdict({(id)kSecClass, (id)kSecClassCertificate},
                                        {(id)kSecAttrPublicKeyHash, pubKeyDigest.asData});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (MYIdentity*) identityWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [MYKeyEnumerator firstItemWithQuery:
                $mdict({(id)kSecClass, (id)kSecClassIdentity},
                       {(id)kSecAttrApplicationLabel/*kSecAttrPublicKeyHash*/, pubKeyDigest.asData})];
}

- (NSEnumerator*) enumerateIdentities {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassIdentity});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (NSEnumerator*) enumerateSymmetricKeys {
    NSMutableDictionary *query = $mdict({(id)kSecAttrKeyClass, (id)kSecAttrKeyClassSymmetric});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (NSEnumerator*) symmetricKeysWithAlias: (NSString*)alias {
    NSMutableDictionary *query = $mdict({(id)kSecAttrKeyClass, (id)kSecAttrKeyClassSymmetric},
                                        {(id)kSecAttrApplicationTag, alias});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}


#pragma mark -
#pragma mark IMPORT:


+ (CFTypeRef) _addItemWithInfo: (NSMutableDictionary*)info {
    // Generally SecItemAdd will fail (return paramErr) if asked to return a regular ref.
    // As a workaround ask for a persistent ref instead, then convert that to regular ref.
    if (![[info objectForKey: (id)kSecReturnRef] boolValue])
        [info setObject: $true forKey: (id)kSecReturnPersistentRef];
    
    CFDataRef itemPersistentRef;
    CFTypeRef item;
    OSStatus err = SecItemAdd((CFDictionaryRef)info, (CFTypeRef*)&itemPersistentRef);
    if (err==errSecDuplicateItem) {
        Log(@"_addItemWithInfo: Keychain claims it's a dup, so look for existing item");
        // it's already in the keychain -- get a reference to it:
		[info removeObjectForKey: (id)kSecReturnPersistentRef];
		[info setObject: $true forKey: (id)kSecReturnRef];
		if (check(SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef *)&item), 
                  @"SecItemCopyMatching")) {
            if (!item)
                Warn(@"_addItemWithInfo: Couldn't find supposedly-duplicate item, info=%@",info);
            Log(@"_addItemWithInfo: SecItemAdd found item; ref=%@", item);//TEMP
            return item;
        }
    } else if (check(err, @"SecItemAdd")) {
        // It was added
        if ([[info objectForKey: (id)kSecReturnPersistentRef] boolValue]) {
            // now get its item ref:
            Log(@"SecItemAdd added item; persistenRef=%@", itemPersistentRef);//TEMP
            info = $mdict({(id)kSecValuePersistentRef, (id)itemPersistentRef},
            {(id)kSecReturnRef, $true});
            err = SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef *)&item);
            CFRelease(itemPersistentRef);
            if (check(err,@"SecItemCopyMatching")) {
                Assert(item!=nil);
                return item;
            }
        } else {
            Log(@"SecItemAdd added item; ref=%@", itemPersistentRef);//TEMP
            return (CFTypeRef)itemPersistentRef;
        }
    }
    Log(@"SecItemAdd failed: info = %@", info); // for help in debugging, dump the input dict
    return NULL;
}


- (MYPublicKey*) importPublicKey: (NSData*)keyData {
    return [[[MYPublicKey alloc] _initWithKeyData: keyData 
                                      forKeychain: (void*)self]
            autorelease];
}

- (MYCertificate*) importCertificate: (NSData*)data
{
    Assert(data);
    
#if 1
    SecCertificateRef cert0 = SecCertificateCreateWithData(NULL, (CFDataRef)data);
    if (!cert0)
        return nil;
    NSMutableDictionary *info = $mdict( {(id)kSecClass, (id)kSecClassCertificate},
                                        {(id)kSecValueRef, (id)cert0});
#else
    NSMutableDictionary *info = $mdict( {(id)kSecClass, (id)kSecClassCertificate},
                                        {(id)kSecAttrCertificateType, $object(CSSM_CERT_X_509v3)},
                                        {(id)kSecAttrCertificateEncoding, $object(CSSM_CERT_ENCODING_BER)},
                                        {(id)kSecValueData, data} );
#endif
    SecCertificateRef cert = (SecCertificateRef) [[self class] _addItemWithInfo: info];
    if (!cert)
        return nil;
    MYCertificate *myCert = [[[MYCertificate alloc] initWithCertificateRef: cert] autorelease];
    AssertEqual(data, myCert.certificateData);  //TEMP for debugging
    return myCert;
}


#pragma mark -
#pragma mark GENERATION:


- (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm
{
    return [MYSymmetricKey _generateSymmetricKeyOfSize: keySizeInBits
                                             algorithm: algorithm inKeychain: self];
}

- (MYPrivateKey*) generateRSAKeyPairOfSize: (unsigned)keySize {
    return [MYPrivateKey _generateRSAKeyPairOfSize: keySize inKeychain: self];
}


#pragma mark -
#pragma mark REMOVING:


- (BOOL) removeAllCertificates {
    NSDictionary *query = $dict({(id)kSecClass, (id)kSecClassCertificate});
    return check(SecItemDelete((CFDictionaryRef)query),  @"SecItemDelete");
}

- (BOOL) removeAllKeys {
    NSDictionary *query = $dict({(id)kSecClass, (id)kSecClassKey});
    return check(SecItemDelete((CFDictionaryRef)query), @"SecItemDelete");
}


@end



#pragma mark -
@implementation MYKeyEnumerator

- (id) initWithQuery: (NSMutableDictionary*)query {
    self = [super init];
    if (self) {
        _itemClass = (CFTypeRef)[query objectForKey: (id)kSecAttrKeyClass];
        if (_itemClass)
            [query setObject: (id)kSecClassKey forKey: (id)kSecClass];
        else
            _itemClass = (CFTypeRef)[query objectForKey: (id)kSecClass];
        Assert(_itemClass);
        CFRetain(_itemClass);

        // Ask for all results unless caller specified fewer:
        CFTypeRef limit = [query objectForKey: (id)kSecMatchLimit];
        if (! limit) {
            limit = kSecMatchLimitAll;
            [query setObject: (id)limit forKey: (id)kSecMatchLimit];
        }
        
        [query setObject: $true forKey: (id)kSecReturnRef];
        
        OSStatus err = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef*)&_results);
        if (err && err != errSecItemNotFound) {
            check(err,@"SecItemCopyMatching");
            [self release];
            return nil;
        }
        //Log(@"Enumerator results = %@", _results);
        
        if (_results && CFEqual(limit,kSecMatchLimitOne)) {
            // If you ask for only one, it gives you the object back instead of an array:
            CFArrayRef resultsArray = CFArrayCreate(NULL, (const void**)&_results, 1, 
                                                    &kCFTypeArrayCallBacks);
            CFRelease(_results);
            _results = resultsArray;
        }
    }
    return self;
}

+ (id) firstItemWithQuery: (NSMutableDictionary*)query {
    [query setObject: (id)kSecMatchLimitOne forKey: (id)kSecMatchLimit];
    MYKeyEnumerator *e = [[self alloc] initWithQuery: query];
    MYKeychainItem *item = [e.nextObject retain];
    [e release];
    return [item autorelease];
}    

- (void) dealloc
{
    [_currentObject release];
    CFRelease(_itemClass);
    if (_results) CFRelease(_results);
    [super dealloc];
}


- (BOOL) _verifyPublicKeyRef: (MYKeychainItemRef)itemRef {
    // Enumerating the keychain sometimes returns public-key refs that give not-found errors
    // when you try to use them for anything. As a workaround, detect these early on before
    // even creating a MYPublicKey:
    NSDictionary *info = $dict({(id)kSecValueRef, (id)itemRef},
                               {(id)kSecReturnAttributes, $true});
    CFDictionaryRef attrs = NULL;
    OSStatus err = SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef*)&attrs);
    if (attrs) CFRelease(attrs);
    if (err == errSecItemNotFound) {
        Log(@"MYKeyEnumerator: Ignoring bogus(?) key with ref %p", itemRef);
        return NO;
    } else
        return YES;
}        

- (id) nextObject {
    if (!_results)
        return nil;
    setObj(&_currentObject,nil);
    while (_currentObject==nil && _index < CFArrayGetCount(_results)) {
        CFTypeRef found = CFArrayGetValueAtIndex(_results, _index++); 
        if (_itemClass == kSecAttrKeyClassPrivate) {
            _currentObject = [[MYPrivateKey alloc] initWithKeyRef: (SecKeyRef)found];
        } else if (_itemClass == kSecAttrKeyClassPublic) {
            if ([self _verifyPublicKeyRef: found])
                _currentObject = [[MYPublicKey alloc] initWithKeyRef: (SecKeyRef)found];
        } else if (_itemClass == kSecAttrKeyClassSymmetric) {
            _currentObject = [[MYSymmetricKey alloc] initWithKeyRef: (SecKeyRef)found];
        } else if (_itemClass == kSecClassCertificate) {
            _currentObject = [[MYCertificate alloc] initWithCertificateRef: (SecCertificateRef)found];
        } else if (_itemClass == kSecClassIdentity) {
            _currentObject = [[MYIdentity alloc] initWithIdentityRef: (SecIdentityRef)found];
        } else  {
            Assert(NO,@"Unknown _itemClass: %@",_itemClass);
        }
    }
    return _currentObject;
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
