//
//  MYKeyPair-iPhone.m
//  MYNetwork-iPhone
//
//  Created by Jens Alfke on 3/22/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//


#import "MYKeyPair.h"
#import "MYCrypto_Private.h"

#if USE_IPHONE_API


@implementation MYKeyPair


+ (MYKeyPair*) _generateKeyPairOfSize: (unsigned)keySize inKeychain: (MYKeychain*)keychain {
    Assert( keySize == 512 || keySize == 1024 || keySize == 2048, @"Unsupported key size %u", keySize );
    SecKeyRef pubKey=NULL, privKey=NULL;
    OSStatus err;
    NSDictionary *pubKeyAttrs = $dict({(id)kSecAttrIsPermanent, $true});
    NSDictionary *privKeyAttrs = $dict({(id)kSecAttrIsPermanent, $true});
    NSDictionary *keyAttrs = $dict( {(id)kSecAttrKeyType, (id)kSecAttrKeyTypeRSA},
                                    {(id)kSecAttrKeySizeInBits, $object(keySize)},
                                    {(id)kSecPublicKeyAttrs, pubKeyAttrs},
                                    {(id)kSecPrivateKeyAttrs, privKeyAttrs} );
    err = SecKeyGeneratePair((CFDictionaryRef)keyAttrs,&pubKey,&privKey);
    if (err) {
        Warn(@"Failed to create key-pair: %i", err);
        return nil;
    } else
        return [[[self alloc] initWithPublicKeyRef: pubKey privateKeyRef: privKey] autorelease];
}

- (id) initWithPublicKeyRef: (SecKeyRef)publicKey privateKeyRef: (SecKeyRef)privateKey {
    self = [super initWithKeyRef: publicKey];
    if (self) {
        NSParameterAssert(privateKey);
        _privateKey = (SecKeyRef) CFRetain(privateKey);
    }
    return self;
}


- (NSArray*) _itemList {
    return $array((id)_privateKey,(id)self.keyRef);
}


@synthesize privateKeyRef=_privateKey;


- (NSData*) decryptData: (NSData*)data {
    return _crypt(_privateKey,data,kCCDecrypt);
}
    

- (NSData*) signData: (NSData*)data {
    Assert(data);
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes,data.length, digest);

    size_t sigLen = 1024;
    uint8_t sigBuf[sigLen];
    OSStatus err = SecKeyRawSign(_privateKey, kSecPaddingPKCS1SHA1,
                                   digest,sizeof(digest), //data.bytes, data.length,
                                   sigBuf, &sigLen);
    if(err) {
        Warn(@"SecKeyRawSign failed: %i",err);
        return nil;
    } else
        return [NSData dataWithBytes: sigBuf length: sigLen];
}


@end


#endif USE_IPHONE_API
