//
//  KeyPair.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeyPair.h"
#import "MYCrypto_Private.h"
#import <CommonCrypto/CommonDigest.h>

#if !USE_IPHONE_API


#pragma mark -

@implementation MYKeyPair


+ (MYKeyPair*) _generateRSAKeyPairOfSize: (unsigned)keySize
                            inKeychain: (SecKeychainRef)keychain {
    Assert( keySize == 512 || keySize == 1024 || keySize == 2048, @"Unsupported key size %u", keySize );
    SecKeyRef pubKey=NULL, privKey=NULL;
    OSStatus err;
    err = SecKeyCreatePair(keychain, CSSM_ALGID_RSA, keySize, 0LL,
                           CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_VERIFY,        // public key
                           CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_PERMANENT,
                           CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_SIGN,          // private key
                           CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_SENSITIVE | CSSM_KEYATTR_PERMANENT,
                           NULL, // SecAccessRef
                           &pubKey, &privKey);
    if (!check(err, @"SecKeyCreatePair")) {
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

- (id) _initWithPublicKeyData: (NSData*)pubKeyData
                   privateKey: (SecKeyRef)privateKey 
                  forKeychain: (SecKeychainRef)keychain {
    if (!privateKey) {
        [self release];
        return nil;
    }
    self = [self _initWithKeyData: pubKeyData forKeychain: keychain];
    if (self) {
        _privateKey = privateKey;
    } else {
        SecKeychainItemDelete((SecKeychainItemRef)privateKey);
        CFRelease(privateKey);
    }
    return self;
}


// The public API for this is in MYKeychain.
- (id) _initWithPublicKeyData: (NSData*)pubKeyData 
               privateKeyData: (NSData*)privKeyData
                  forKeychain: (SecKeychainRef)keychain 
                   alertTitle: (NSString*)title
                  alertPrompt: (NSString*)prompt
{
    // Try to import the private key first, since the user might cancel the passphrase alert.
    SecKeyImportExportParameters params = {
        .flags = kSecKeySecurePassphrase,
        .alertTitle = (CFStringRef) title,
        .alertPrompt = (CFStringRef) prompt
    };
    SecKeyRef privateKey = importKey(privKeyData,kSecItemTypePrivateKey,keychain,&params);
    return [self _initWithPublicKeyData: pubKeyData privateKey: privateKey forKeychain: keychain];
}

// This method is for testing, so unit-tests don't require user intervention.
// It's deliberately not made public, to discourage clients from trying to manage the passphrases
// themselves (this is less secure than letting the Security agent do it.)
- (id) _initWithPublicKeyData: (NSData*)pubKeyData 
               privateKeyData: (NSData*)privKeyData
                  forKeychain: (SecKeychainRef)keychain 
                   passphrase: (NSString*)passphrase
{
    SecKeyImportExportParameters params = {
        .passphrase = (CFStringRef) passphrase,
    };
    SecKeyRef privateKey = importKey(privKeyData,kSecItemTypePrivateKey,keychain,&params);
    return [self _initWithPublicKeyData: pubKeyData privateKey: privateKey forKeychain: keychain];
}


- (void) dealloc
{
    if (_privateKey) CFRelease(_privateKey);
    [super dealloc];
}


- (NSUInteger)hash {
    // Ensure that a KeyPair doesn't hash the same as its corresponding PublicKey:
    return super.hash ^ 0xFFFFFFFF;
}


- (MYPublicKey*) asPublicKey {
    return [[[MYPublicKey alloc] initWithKeyRef: self.keyRef] autorelease];
}


- (NSData*) exportPrivateKeyInFormat: (SecExternalFormat)format
                             withPEM: (BOOL)withPEM
                          alertTitle: (NSString*)title
                         alertPrompt: (NSString*)prompt
{
    SecKeyImportExportParameters params = {
        .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
        .flags = kSecKeySecurePassphrase,
        .alertTitle = (CFStringRef)title,
        .alertPrompt = (CFStringRef)prompt
    };
    CFDataRef data = NULL;
    if (check(SecKeychainItemExport(_privateKey, //$array((id)_publicKey,(id)_privateKey),
                                    format, (withPEM ?kSecItemPemArmour :0), 
                                    &params, &data),
              @"SecKeychainItemExport"))
        return [(id)CFMakeCollectable(data) autorelease];
    else
        return nil;
}

- (NSData*) exportPrivateKey {
    return [self exportPrivateKeyInFormat: kSecFormatWrappedOpenSSL withPEM: YES
                               alertTitle: @"Export Private Key"
                              alertPrompt: @"Enter a passphrase to protect the private-key file.\n"
            "You will need to re-enter the passphrase later when importing the key from this file, "
            "so keep it in a safe place."];
    //FIX: Should make these messages localizable.
}


- (NSData*) _exportPrivateKeyInFormat: (SecExternalFormat)format
                              withPEM: (BOOL)withPEM
                           passphrase: (NSString*)passphrase
{
    SecKeyImportExportParameters params = {
        .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
        .passphrase = (CFStringRef)passphrase
    };
    CFDataRef data = NULL;
    if (check(SecKeychainItemExport(_privateKey,
                                    format, (withPEM ?kSecItemPemArmour :0), 
                                    &params, &data),
              @"SecKeychainItemExport"))
        return [(id)CFMakeCollectable(data) autorelease];
    else
        return nil;
}

- (BOOL) removeFromKeychain {
    return check(SecKeychainItemDelete((SecKeychainItemRef)_privateKey), @"delete private key")
        && [super removeFromKeychain];
}


- (SecKeyRef) privateKeyRef {
    return _privateKey;
}


- (NSData*) decryptData: (NSData*)data {
    return _crypt(_privateKey,data,kCCDecrypt);
}
    

- (NSData*) signData: (NSData*)data {
    Assert(data);
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes,data.length, digest);
    
    NSData *signature = nil;
    CSSM_CC_HANDLE ccHandle = cssmCreateSignatureContext(_privateKey);
    if (!ccHandle) return nil;
    CSSM_DATA original = {data.length, (void*)data.bytes};
    CSSM_DATA result = {0,NULL};
    if (checkcssm(CSSM_SignData(ccHandle, &original, 1, CSSM_ALGID_NONE, &result), @"CSSM_SignData"))
        signature = [NSData dataWithBytesNoCopy: result.Data length: result.Length
                                   freeWhenDone: YES];
    CSSM_DeleteContext(ccHandle);
    return signature;
}


- (BOOL) setValue: (NSString*)valueStr ofAttribute: (SecKeychainAttrType)attr {
    return [super setValue: valueStr ofAttribute: attr]
        && [[self class] _setAttribute: attr 
                                ofItem: (SecKeychainItemRef)_privateKey
                           stringValue: valueStr];
}


@end


#endif !USE_IPHONE_API




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
