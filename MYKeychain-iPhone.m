//
//  MYKeychain-iPhone.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/31/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCrypto_Private.h"
#import "MYDigest.h"

#if USE_IPHONE_API


@interface MYKeyEnumerator : NSEnumerator
{
    CFArrayRef _results;
    CFTypeRef _itemClass;
    CFIndex _index;
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
                $mdict({(id)kSecClass, (id)kSecClassKey},
                      {(id)kSecAttrPublicKeyHash, pubKeyDigest.asData},
                      {(id)kSecReturnRef, $true})];
}   

- (NSEnumerator*) enumeratePublicKeys {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPublic},
                                {(id)kSecMatchLimit, (id)kSecMatchLimitAll},
                                {(id)kSecReturnRef, $true});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}


- (MYKeyPair*) keyPairWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [MYKeyEnumerator firstItemWithQuery:
                $mdict({(id)kSecClass, (id)kSecClassKey},
                      {(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPrivate},
                      {(id)kSecAttrPublicKeyHash, pubKeyDigest.asData},
                      {(id)kSecReturnRef, $true})];
}

- (NSEnumerator*) enumerateKeyPairs {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)kSecAttrKeyClassPrivate},
                                {(id)kSecMatchLimit, (id)kSecMatchLimitAll},
                                {(id)kSecReturnRef, $true});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (MYCertificate*) certificateWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [MYKeyEnumerator firstItemWithQuery:
                $mdict({(id)kSecClass, (id)kSecClassCertificate},
                      {(id)kSecAttrPublicKeyHash, pubKeyDigest.asData},
                      {(id)kSecReturnRef, $true})];
}

- (NSEnumerator*) enumerateCertificates {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassCertificate},
                                {(id)kSecMatchLimit, (id)kSecMatchLimitAll},
                                {(id)kSecReturnRef, $true});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (NSEnumerator*) enumerateSymmetricKeys {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)kSecAttrKeyClassSymmetric},
                                {(id)kSecMatchLimit, (id)kSecMatchLimitAll},
                                {(id)kSecReturnRef, $true});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}

- (NSEnumerator*) symmetricKeysWithAlias: (NSString*)alias {
    NSMutableDictionary *query = $mdict({(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyClass, (id)kSecAttrKeyClassSymmetric},
                                {(id)kSecAttrApplicationTag, alias},
                                {(id)kSecMatchLimit, (id)kSecMatchLimitAll},
                                {(id)kSecReturnRef, $true});
    return [[[MYKeyEnumerator alloc] initWithQuery: query] autorelease];
}


#pragma mark -
#pragma mark IMPORT:


- (MYPublicKey*) importPublicKey: (NSData*)keyData {
    return [[[MYPublicKey alloc] _initWithKeyData: keyData 
                                      forKeychain: self]
            autorelease];
}

- (MYCertificate*) importCertificate: (NSData*)data
{
    Assert(data);
    NSDictionary *info = $dict( {(id)kSecClass, (id)kSecClassCertificate},
                                {(id)kSecValueData, data},
                                {(id)kSecReturnRef, $true} );
    SecCertificateRef cert;
    if (!check(SecItemAdd((CFDictionaryRef)info, (CFTypeRef*)&cert), @"SecItemAdd"))
        return nil;
    return [[[MYCertificate alloc] initWithCertificateRef: cert] autorelease];
}


#pragma mark -
#pragma mark GENERATION:


- (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm
{
    return [MYSymmetricKey _generateSymmetricKeyOfSize: keySizeInBits
                                             algorithm: algorithm inKeychain: self];
}

- (MYKeyPair*) generateRSAKeyPairOfSize: (unsigned)keySize {
    return [MYKeyPair _generateRSAKeyPairOfSize: keySize inKeychain: self];
}



@end



#pragma mark -
@implementation MYKeyEnumerator

- (id) initWithQuery: (NSMutableDictionary*)query {
    self = [super init];
    if (self) {
        if (![query objectForKey: (id)kSecMatchLimit])
            [query setObject: (id)kSecMatchLimitAll forKey: (id)kSecMatchLimit];
        OSStatus err = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef*)&_results);
        if (err && err != errSecItemNotFound) {
            check(err,@"SecItemCopyMatching");
            [self release];
            return nil;
        }
        if (_results) CFRetain(_results);
        _itemClass = (CFTypeRef)[query objectForKey: (id)kSecClass];
        if (_itemClass == kSecClassKey)
            _itemClass = (CFTypeRef)[query objectForKey: (id)kSecAttrKeyClass];
        if (_itemClass) CFRetain(_itemClass);
    }
    return self;
}

+ (id) firstItemWithQuery: (NSMutableDictionary*)query {
    MYKeyEnumerator *e = [[self alloc] initWithQuery: query];
    MYKeychainItem *item = e.nextObject;
    [e release];
    return item;
}    

- (void) dealloc
{
    if (_itemClass) CFRelease(_itemClass);
    if (_results) CFRelease(_results);
    [super dealloc];
}


- (id) nextObject {
    if (!_results)
        return nil;
    MYKeychainItem *next = nil;
    for (; next==nil && _index < CFArrayGetCount(_results); _index++) {
        CFTypeRef found = CFArrayGetValueAtIndex(_results, _index); 
        if (_itemClass == kSecAttrKeyClassPrivate) {
            MYSHA1Digest *digest = [MYPublicKey _digestOfKey: (SecKeyRef)found];
            if (digest) {
                MYPublicKey *publicKey = [[MYKeychain defaultKeychain] publicKeyWithDigest: digest];
                if (publicKey)
                    next = [[[MYKeyPair alloc] initWithPublicKeyRef: publicKey.keyRef
                                                     privateKeyRef: (SecKeyRef)found]
                           autorelease];
                else {
                    // The matching public key won't turn up if it's embedded in a certificate;
                    // I'd have to search for certs if I wanted to look that up. Skip it for now.
                    //Warn(@"Couldn't find matching public key for private key!");
                }
            }
            break;
        } else if (_itemClass == kSecAttrKeyClassPublic) {
            next = [[[MYPublicKey alloc] initWithKeyRef: (SecKeyRef)found] autorelease];
            break;
        } else if (_itemClass == kSecAttrKeyClassSymmetric) {
            next = [[[MYSymmetricKey alloc] initWithKeyRef: (SecKeyRef)found] autorelease];
            break;
        } else if (_itemClass == kSecClassCertificate) {
            next = [[[MYCertificate alloc] initWithCertificateRef: (SecCertificateRef)found] autorelease];
            break;
        }
        CFRelease(found);
    }
    return next;
}


@end

#endif USE_IPHONE_API


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
