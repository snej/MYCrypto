//
//  MYSymmetricKey.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/2/09.
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
#else
#import <Security/cssmtype.h>
#endif

static const CSSM_ALGORITHMS kCSSMAlgorithms[] = {
    CSSM_ALGID_AES, CSSM_ALGID_DES, CSSM_ALGID_3DES_3KEY, CSSM_ALGID_CAST, CSSM_ALGID_RC4
};

static const char *kCCAlgorithmNames[] = {"AES", "DES", "DES^3", "CAST", "RC4"};


#pragma mark -
@implementation MYSymmetricKey


- (id) _initWithKeyData: (NSData*)keyData
              algorithm: (CCAlgorithm)algorithm
             inKeychain: (MYKeychain*)keychain
{
    Assert(algorithm <= kCCAlgorithmRC4);
    Assert(keyData);
    SecKeyRef keyRef = NULL;
#if MYCRYPTO_USE_IPHONE_API
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
    //{(id)kSecAttrApplicationTag, [@"foo" dataUsingEncoding: NSUTF8StringEncoding]}, //TEMP
                                    {(id)kSecReturnPersistentRef, $true});
    if (!check(SecItemAdd((CFDictionaryRef)keyAttrs, (CFTypeRef*)&keyRef), @"SecItemAdd")) {
        [self release];
        return nil;
    }
    Log(@"SecItemAdd returned %@", keyRef);//TEMP
    Assert(keyRef, @"SecItemAdd didn't return anything");
#else
    Assert(NO,@"Unimplemented"); //FIX
    /* The technique below doesn't work, because there's no way to tell SecKeychainItemImport
       what algorithm to use when importing a raw key. Still looking for a solution... --jpa 4/2009
    SecKeyImportExportParameters params = {};
    keyRef = importKey(keyData, kSecItemTypeSessionKey, keychain.keychainRefOrDefault, &params);
    if (!keyRef) {
        [self release];
        return nil;
    }
     */
#endif
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
#if MYCRYPTO_USE_IPHONE_API
    return [[[self alloc] _initWithKeyData: [MYCryptor randomKeyOfLength: keySizeInBits]
                                 algorithm: algorithm
                                inKeychain: keychain]
                    autorelease];
#else
    Assert(algorithm <= kCCAlgorithmRC4);
    CSSM_KEYATTR_FLAGS flags = CSSM_KEYATTR_EXTRACTABLE;
    if (keychain)
        flags |= CSSM_KEYATTR_PERMANENT | CSSM_KEYATTR_SENSITIVE | CSSM_KEYATTR_EXTRACTABLE;
    CSSM_KEYUSE usage = CSSM_KEYUSE_ANY;
    SecKeyRef keyRef = NULL;
    if (!check(SecKeyGenerate(keychain.keychainRefOrDefault,    // nil kc generates a transient key
                              kCSSMAlgorithms[algorithm],
                              keySizeInBits, 
                              0, usage, flags, NULL, &keyRef),
               @"SecKeyGenerate")) {
        return nil;
    }
    return [[[self alloc] initWithKeyRef: keyRef] autorelease];
#endif
}

+ (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm {
    return [self _generateSymmetricKeyOfSize: keySizeInBits
                                   algorithm: algorithm
                                  inKeychain: nil];
}


#if !TARGET_OS_IPHONE
- (NSData*) exportKeyInFormat: (SecExternalFormat)format
                      withPEM: (BOOL)withPEM
{
    SecKeyImportExportParameters params = {
        .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
        .flags = kSecKeySecurePassphrase,
    };
    CFDataRef data = NULL;
    if (check(SecKeychainItemExport(self.keyRef,
                                    format, (withPEM ?kSecItemPemArmour :0), 
                                    &params, &data),
              @"SecKeychainItemExport"))
        return [(id)CFMakeCollectable(data) autorelease];
    else
        return nil;
}
#endif


- (SecExternalItemType) keyType {
#if MYCRYPTO_USE_IPHONE_API
    return kSecAttrKeyClassSymmetric;
#else
    return kSecItemTypeSessionKey;
#endif
}

- (CCAlgorithm) algorithm {
    CSSM_ALGORITHMS cssmAlg;
#if MYCRYPTO_USE_IPHONE_API
    id keyType = [self _attribute: kSecAttrKeyType];
    Assert(keyType!=nil, @"Key has no kSecAttrKeyType");
    cssmAlg = [keyType unsignedIntValue];
#else
    cssmAlg = self.cssmKey->KeyHeader.AlgorithmId;
#endif
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
#if MYCRYPTO_USE_IPHONE_API
    id keySize = [self _attribute: kSecAttrKeySizeInBits];
    Assert(keySize!=nil, @"Key has no kSecAttrKeySizeInBits");
    return [keySize unsignedIntValue];
#else
    const CSSM_KEY *key = self.cssmKey;
    Assert(key);
    return key->KeyHeader.LogicalKeySizeInBits;
#endif
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


/* (Turned out I could just use SecKeyExport for this.)
 
static NSData* wrap(SecKeyRef key, CSSM_ALGORITHMS algorithm) {
    CAssert(key);
    const CSSM_KEY* cssmKey;
    const CSSM_ACCESS_CREDENTIALS *credentials;
    CSSM_CSP_HANDLE cspHandle;
    CSSM_CC_HANDLE ccHandle;
    if (!check(SecKeyGetCSSMKey(key, &cssmKey), @"GetCSSMKey")
        || !check(SecKeyGetCredentials(key, 
                                       CSSM_ACL_AUTHORIZATION_EXPORT_WRAPPED, 
                                       kSecCredentialTypeDefault,
                                       &credentials), @"GetCredentials")
        || !check(SecKeyGetCSPHandle(key, &cspHandle), @"GetCSPHandle")
        
        || !checkcssm(CSSM_CSP_CreateSymmetricContext(cspHandle, algorithm, CSSM_ALGMODE_WRAP,
                                                      NULL, NULL, NULL,
                                                      CSSM_PADDING_NONE, NULL, &ccHandle),
                      @"CSSM_CSP_CreateSymmetricContext"))
        return nil;
    
    CSSM_WRAP_KEY wrapped;
    NSData *result = nil;
    if(checkcssm(CSSM_WrapKey(ccHandle, credentials, cssmKey, NULL, &wrapped),
                 @"CSSM_WrapKey")) {
        result = [NSData dataWithBytes: wrapped.KeyData.Data 
                                length: wrapped.KeyData.Length];
    }
    CSSM_DeleteContext(ccHandle);
    return result;
}
*/
