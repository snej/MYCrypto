//
//  MYSymmetricKey-iPhone.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/17/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYSymmetricKey.h"
#import "MYCryptor.h"
#import "MYCrypto_Private.h"

#if MYCRYPTO_USE_IPHONE_API


typedef uint32_t CSSM_ALGORITHMS;
enum {
// Taken from cssmtype.h in OS X 10.5 SDK:
	CSSM_ALGID_NONE =					0x00000000L,
	CSSM_ALGID_DES =					CSSM_ALGID_NONE + 14,
	CSSM_ALGID_3DES_3KEY_EDE =			CSSM_ALGID_NONE + 17,
	CSSM_ALGID_3DES_3KEY =           	CSSM_ALGID_3DES_3KEY_EDE,
	CSSM_ALGID_RC4 =					CSSM_ALGID_NONE + 25,
	CSSM_ALGID_CAST =					CSSM_ALGID_NONE + 27,
	CSSM_ALGID_VENDOR_DEFINED =			CSSM_ALGID_NONE + 0x80000000L,
	CSSM_ALGID_AES
};

static const CSSM_ALGORITHMS kCSSMAlgorithms[] = {
CSSM_ALGID_AES, CSSM_ALGID_DES, CSSM_ALGID_3DES_3KEY, CSSM_ALGID_CAST, CSSM_ALGID_RC4
};

static const char *kCCAlgorithmNames[] = {"AES", "DES", "DES^3", "CAST", "RC4"};


@implementation MYSymmetricKey


- (id) _initWithKeyData: (NSData*)keyData
              algorithm: (CCAlgorithm)algorithm
             inKeychain: (MYKeychain*)keychain
{
    Assert(algorithm <= kCCAlgorithmRC4);
    Assert(keyData);
    NSNumber *keySizeInBits = [NSNumber numberWithUnsignedInt: keyData.length * 8];
    NSDictionary *keyAttrs = $dict( {(id)kSecClass, (id)kSecClassKey},
                                    //{(id)kSecAttrKeyClass, (id)kSecAttrKeyClassSymmetric},
                                    {(id)kSecAttrKeyType, [NSNumber numberWithUnsignedInt: kCSSMAlgorithms[algorithm]]},
                                    {(id)kSecAttrKeySizeInBits, keySizeInBits},
                                    {(id)kSecAttrEffectiveKeySize, keySizeInBits},
                                    {(id)kSecAttrIsPermanent, keychain ?$true :$false},
                                    {(id)kSecAttrCanEncrypt, $true},
                                    {(id)kSecAttrCanDecrypt, $true},
                                    {(id)kSecAttrCanWrap, $false},
                                    {(id)kSecAttrCanUnwrap, $false},
                                    {(id)kSecAttrCanDerive, $false},
                                    {(id)kSecAttrCanSign, $false},
                                    {(id)kSecAttrCanVerify, $false},
                                    {(id)kSecValueData, keyData},
                                    {(id)kSecReturnPersistentRef, $true});
    SecKeyRef keyRef = NULL;
    if (!check(SecItemAdd((CFDictionaryRef)keyAttrs, (CFTypeRef*)&keyRef), @"SecItemAdd")) {
        [self release];
        return nil;
    }
    Assert(keyRef, @"SecItemAdd didn't return anything");
    self = [self initWithKeyRef: keyRef];
    CFRelease(keyRef);
    return self;
}

- (id) initWithKeyData: (NSData*)keyData
             algorithm: (CCAlgorithm)algorithm
{
    return [self _initWithKeyData: keyData algorithm: algorithm inKeychain: nil];
}

+ (MYSymmetricKey*) _generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                      algorithm: (CCAlgorithm)algorithm
                                     inKeychain: (MYKeychain*)keychain
{
    return [[[self alloc] _initWithKeyData: [MYCryptor randomKeyOfLength: keySizeInBits]
                                 algorithm: algorithm
                                inKeychain: keychain]
                    autorelease];
}

+ (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm {
    return [self _generateSymmetricKeyOfSize: keySizeInBits
                                   algorithm: algorithm
                                  inKeychain: nil];
}


- (SecExternalItemType) keyType {
    return kSecAttrKeyClassSymmetric;
}

- (CCAlgorithm) algorithm {
    CSSM_ALGORITHMS cssmAlg;
    id keyType = [self _attribute: kSecAttrKeyType];
    Assert(keyType!=nil, @"Key has no kSecAttrKeyType");
    cssmAlg = [keyType unsignedIntValue];
    switch(cssmAlg) {
        case CSSM_ALGID_AES:
            return kCCAlgorithmAES128;
        case CSSM_ALGID_DES:
            return kCCAlgorithmDES;	
        case CSSM_ALGID_3DES_3KEY:
            return kCCAlgorithm3DES;
        case CSSM_ALGID_CAST:
            return kCCAlgorithmCAST;
        case CSSM_ALGID_RC4:
            return kCCAlgorithmRC4;	
        default:
            Warn(@"CSSM_ALGORITHMS #%u doesn't map to any CCAlgorithm", cssmAlg);
            return (CCAlgorithm)-1;
    }
}

- (const char*) algorithmName {
    CCAlgorithm a = self.algorithm;
    if (a >= 0 && a <= kCCAlgorithmRC4)
        return kCCAlgorithmNames[a];
    else
        return "???";
}

- (unsigned) keySizeInBits {
    id keySize = [self _attribute: kSecAttrKeySizeInBits];
    Assert(keySize!=nil, @"Key has no kSecAttrKeySizeInBits");
    return [keySize unsignedIntValue];
}


- (NSString*) description {
    return $sprintf(@"%@[%u-bit %s]", [self class], self.keySizeInBits, self.algorithmName);
}


- (NSData*) _cryptData: (NSData*)data operation: (CCOperation)op options: (CCOptions)options
{
    NSData *keyData = self.keyData;
    Assert(keyData, @"Couldn't get key data");
    NSMutableData *output = [NSMutableData dataWithLength: data.length + 256];
    size_t bytesWritten = 0;
    CCCryptorStatus status = CCCrypt(op, self.algorithm, options, 
                                     keyData.bytes, keyData.length, NULL,
                                     data.bytes, data.length, output.mutableBytes, output.length,
                                     &bytesWritten);
    if (status) {
        Warn(@"MYSymmetricKey: CCCrypt returned error %i",status);
        return nil;
    }
    output.length = bytesWritten;
    return output;
}

- (NSData*) encryptData: (NSData*)data {
    return [self _cryptData: data operation: kCCEncrypt options: kCCOptionPKCS7Padding];
}


- (NSData*) decryptData: (NSData*)data {
    return [self _cryptData: data operation: kCCDecrypt options: kCCOptionPKCS7Padding];
}


@end


#endif MYCRYPTO_USE_IPHONE_API
