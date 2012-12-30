//
//  MYKeychain.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/23/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeychain.h"
#import "MYCrypto_Private.h"
#import "MYDigest.h"
#import "MYIdentity.h"


#if !MYCRYPTO_USE_IPHONE_API


@interface MYKeyEnumerator : NSEnumerator
{
    @private
    MYKeychain *_keychain;
    SecKeychainSearchRef _search;
    SecItemClass _itemClass;
}

- (id) initWithKeychain: (MYKeychain*)keychain
              itemClass: (SecItemClass)itemClass
             attributes: (SecKeychainAttribute[])attributes 
                  count: (unsigned)count;
@end


@interface MYIdentityEnumerator : NSEnumerator
{
    @private
    SecIdentitySearchRef _searchRef;
}

- (id) initWithKeychain: (MYKeychain*)keychain keyUsage: (CSSM_KEYUSE)keyUsage;
@end




@implementation MYKeychain


- (id) initWithKeychainRef: (SecKeychainRef)keychainRef
{
    self = [super init];
    if (self != nil) {
        if (keychainRef) {
            CFRetain(keychainRef);
            _keychain = keychainRef;
        }
    }
    return self;
}

+ (MYKeychain*) _readableKeychainWithRef: (SecKeychainRef)keychainRef fromPath: (NSString*)path {
    if (!keychainRef)
        return nil;
    SecKeychainStatus status;
    BOOL ok = check(SecKeychainGetStatus(keychainRef, &status), @"SecKeychainGetStatus");
    if (ok && !(status & kSecReadPermStatus)) {
        Warn(@"Can't open keychain at %@ : not readable (status=%i)", path,status);
        ok = NO;
    }
    MYKeychain *keychain = nil;
    if (ok)
        keychain = [[self alloc] initWithKeychainRef: keychainRef];
    CFRelease(keychainRef);
    return keychain;
}

+ (MYKeychain*) openKeychainAtPath: (NSString*)path
{
    Assert(path);
    SecKeychainRef keychainRef = NULL;
    if (!check(SecKeychainOpen(path.fileSystemRepresentation, &keychainRef), @"SecKeychainOpen"))
        return nil;
    return [self _readableKeychainWithRef: keychainRef fromPath: path];
}

+ (MYKeychain*) createKeychainAtPath: (NSString*)path
                        withPassword: (NSString*)password
{
    Assert(path);
    const char *passwordStr = [password UTF8String];
    SecKeychainRef keychainRef = NULL;
    if (!check(SecKeychainCreate(path.fileSystemRepresentation,
                                 passwordStr ?(UInt32)strlen(passwordStr) :0,
                                 passwordStr, 
                                 (password==nil), 
                                 NULL, 
                                 &keychainRef),
               @"SecKeychainCreate"))
        return nil;
    return [self _readableKeychainWithRef: keychainRef fromPath: path];
}

- (BOOL) deleteKeychainFile {
    Assert(_keychain);
    return check(SecKeychainDelete(_keychain), @"SecKeychainDelete");
}


- (void) dealloc
{
    if (_keychain) CFRelease(_keychain);
}



+ (MYKeychain*) allKeychains
{
    static MYKeychain *sAllKeychains;
    @synchronized(self) {
        if (!sAllKeychains)
            sAllKeychains = [[self alloc] initWithKeychainRef: nil];
    }
    return sAllKeychains;
}


+ (MYKeychain*) defaultKeychain
{
    static MYKeychain *sDefaultKeychain;
    @synchronized(self) {
        if (!sDefaultKeychain) {
            SecKeychainRef kc = NULL;
            OSStatus err = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser,&kc);
#if TARGET_OS_IPHONE
            // In the simulator, an app is run in a sandbox that has no keychain by default.
            // As a convenience, create one if necessary:
            if (err == errSecNoDefaultKeychain) {
                Log(@"No default keychain in simulator; creating one...");
                NSString *path = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory,
                                                                      NSUserDomainMask, YES) objectAtIndex: 0];
                path = [path stringByAppendingPathComponent: @"MYCrypto.keychain"];
                sDefaultKeychain = [[self createKeychainAtPath: path withPassword: nil] retain];
                Assert(sDefaultKeychain, @"Couldn't create default keychain");
                SecKeychainSetDomainDefault(kSecPreferencesDomainUser, sDefaultKeychain.keychainRef);
                Log(@"...created %@", sDefaultKeychain);
                return sDefaultKeychain;
            }
#endif
            if (!check(err, @"SecKeychainCopyDefault"))
                kc = NULL;

            Assert(kc, @"No default keychain");
            sDefaultKeychain = [[self alloc] initWithKeychainRef: kc];
            CFRelease(kc);
        }
    }
    return sDefaultKeychain;
}


- (id) copyWithZone: (NSZone*)zone {
    // It's not necessary to make copies of Keychain objects. This makes it more efficient
    // to use instances as NSDictionary keys or store them in NSSets.
    return self;
}

- (BOOL) isEqual: (id)obj {
    return (obj == self) || 
            ([obj isKindOfClass: [MYKeychain class]] && CFEqual(_keychain, [obj keychainRef]));
}


- (SecKeychainRef) keychainRef {
    return _keychain;
}


- (SecKeychainRef) keychainRefOrDefault {
    if (_keychain)
        return _keychain;
    else
        return [[[self class] defaultKeychain] keychainRef];
}
    
    
- (NSString*) path {
    if (!_keychain)
        return nil;
    char pathBuf[PATH_MAX];
    UInt32 pathLen = sizeof(pathBuf);
    if (!check(SecKeychainGetPath(_keychain, &pathLen, pathBuf), @"SecKeychainGetPath"))
        return nil;
    return [[NSFileManager defaultManager] stringWithFileSystemRepresentation: pathBuf length: pathLen];
}

- (NSString*) description {
    if (_keychain)
        return $sprintf(@"%@[%p, %@]", [self class], _keychain, self.path);
    else
        return $sprintf(@"%@[all]", [self class]);
}


+ (void) setUserInteractionAllowed: (BOOL)allowed {
    SecKeychainSetUserInteractionAllowed(allowed);
}


#pragma mark -
#pragma mark SEARCHING:


- (MYKeyEnumerator*) enumerateItemsOfClass: (SecItemClass)itemClass 
                                withDigest: (MYSHA1Digest*)pubKeyDigest 
{
    SecKeychainAttribute attr = {.tag= (itemClass==kSecCertificateItemClass ?kSecPublicKeyHashItemAttr :kSecKeyLabel), 
                                 .length= (UInt32)pubKeyDigest.length, 
                                 .data= (void*) pubKeyDigest.bytes};
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: itemClass
                                           attributes: &attr count: 1];
}

- (MYKeychainItem*) itemOfClass: (SecItemClass)itemClass 
                     withDigest: (MYSHA1Digest*)pubKeyDigest 
{
    return [[self enumerateItemsOfClass: itemClass withDigest: pubKeyDigest] nextObject];
}

- (MYPublicKey*) publicKeyWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return (MYPublicKey*) [self itemOfClass: kSecPublicKeyItemClass withDigest: pubKeyDigest];
}   

- (NSEnumerator*) enumeratePublicKeys {
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecPublicKeyItemClass
                                           attributes: NULL count: 0];
}

- (NSEnumerator*) publicKeysWithAlias: (NSString*)alias {
    NSData *utf8 = [alias dataUsingEncoding: NSUTF8StringEncoding];
    SecKeychainAttribute attr = {.tag=kSecKeyAlias, .length=(UInt32)utf8.length, .data=(void*)utf8.bytes};
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecPublicKeyItemClass
                                           attributes: &attr count: 1];
}


- (MYPrivateKey*) privateKeyWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return (MYPrivateKey*) [self itemOfClass: kSecPrivateKeyItemClass withDigest: pubKeyDigest];
}

- (NSEnumerator*) enumeratePrivateKeys {
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecPrivateKeyItemClass
                                           attributes: NULL count: 0];
}

- (MYCertificate*) certificateWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return (MYCertificate*) [self itemOfClass: kSecCertificateItemClass withDigest: pubKeyDigest];
}

- (NSEnumerator*) enumerateCertificatesWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return [self enumerateItemsOfClass: kSecCertificateItemClass withDigest: pubKeyDigest];
}

- (NSEnumerator*) enumerateCertificates {
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecCertificateItemClass
                                           attributes: NULL count: 0];
}

- (MYIdentity*) identityWithDigest: (MYSHA1Digest*)pubKeyDigest {
    for (MYCertificate* cert in [self enumerateCertificatesWithDigest:pubKeyDigest]) {
        MYIdentity* identity = cert.identity;
        if (identity)
            return identity;
    }
    return nil;
}

- (NSEnumerator*) enumerateIdentities {
    return [self enumerateIdentitiesWithKeyUsage: 0];
}

- (NSEnumerator*) enumerateIdentitiesWithKeyUsage: (CSSM_KEYUSE)keyUsage {
    return [[MYIdentityEnumerator alloc] initWithKeychain: self keyUsage: keyUsage];
}

- (NSEnumerator*) enumerateSymmetricKeys {
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecSymmetricKeyItemClass
                                           attributes: NULL count: 0];
}

- (NSEnumerator*) symmetricKeysWithAlias: (NSString*)alias {
    NSData *utf8 = [alias dataUsingEncoding: NSUTF8StringEncoding];
    SecKeychainAttribute attr = {.tag=kSecKeyAlias, .length=(UInt32)utf8.length, .data=(void*)utf8.bytes};
    return [[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecSymmetricKeyItemClass
                                           attributes: &attr count: 1];
}



#pragma mark -
#pragma mark IMPORT:


- (MYPublicKey*) importPublicKey: (NSData*)keyData {
    return [[MYPublicKey alloc] _initWithKeyData: keyData 
                                      forKeychain: self.keychainRefOrDefault];
}

- (MYPrivateKey*) importPublicKey: (NSData*)pubKeyData 
                    privateKey: (NSData*)privKeyData 
                    alertTitle: (NSString*)title
                   alertPrompt: (NSString*)prompt {
    return [[MYPrivateKey alloc] _initWithKeyData: privKeyData
                                     publicKeyData: pubKeyData
                                       forKeychain: self.keychainRefOrDefault
                                        alertTitle: (NSString*)title
                                       alertPrompt: (NSString*)prompt];
}

- (MYPrivateKey*) importPublicKey: (NSData*)pubKeyData 
                    privateKey: (NSData*)privKeyData 
{
    return [self importPublicKey: pubKeyData privateKey: privKeyData
                      alertTitle: @"Import Private Key"
                     alertPrompt: @"To import your saved private key, please re-enter the "
                                   "passphrase you used when you exported it."];
}

- (MYCertificate*) importCertificate: (NSData*)data
                                type: (CSSM_CERT_TYPE) type
                            encoding: (CSSM_CERT_ENCODING) encoding;
{
    MYCertificate *cert = [[MYCertificate alloc] initWithCertificateData: data 
                                                                    type: type
                                                                encoding: encoding];
    if (cert) {
        if (!check(SecCertificateAddToKeychain(cert.certificateRef, self.keychainRefOrDefault),
                   @"SecCertificateAddToKeychain"))
            cert = nil;
    }
    return cert;
}

- (MYCertificate*) importCertificate: (NSData*)data {
    return [self importCertificate: data 
                              type: CSSM_CERT_X_509v3 
                          encoding: CSSM_CERT_ENCODING_BER];
}

- (BOOL) addCertificate: (MYCertificate*)certificate {
    Assert(certificate);
    return check(SecCertificateAddToKeychain(certificate.certificateRef, self.keychainRefOrDefault),
                 @"SecCertificateAddToKeychain");
}


- (MYIdentity*) importIdentity: (NSData*)data
                      inFormat: (SecExternalFormat)format
                         error: (NSError**)outError
{
    return [[MYIdentity alloc] initWithData: data format: format keychain: self error:outError];
}


- (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm
{
    return [MYSymmetricKey _generateSymmetricKeyOfSize: keySizeInBits
                                             algorithm: algorithm inKeychain: self];
}

- (MYPrivateKey*) generateRSAKeyPairOfSize: (unsigned)keySize {
    return [MYPrivateKey _generateRSAKeyPairOfSize: keySize inKeychain: self];
}


- (CSSM_CSP_HANDLE) CSPHandle {
    CSSM_CSP_HANDLE cspHandle = 0;
    Assert(check(SecKeychainGetCSPHandle(self.keychainRefOrDefault, &cspHandle), @"SecKeychainGetCSPHandle"));
    return cspHandle;
}


@end



#pragma mark -
@implementation MYKeyEnumerator

- (id) initWithKeychain: (MYKeychain*)keychain
              itemClass: (SecItemClass)itemClass
             attributes: (SecKeychainAttribute[])attributes 
                  count: (unsigned)count {
    self = [super init];
    if (self) {
        _keychain = keychain;
        _itemClass = itemClass;
        SecKeychainAttributeList list = {.count=count, .attr=attributes};
        if (!check(SecKeychainSearchCreateFromAttributes(keychain.keychainRef,
                                                         itemClass,
                                                         &list,
                                                         &_search),
                   @"SecKeychainSearchCreateFromAttributes")) {
            return nil;
        }
    }
    return self;
}

- (void) dealloc
{
    if (_search) CFRelease(_search);
}



- (id) nextObject {
    if (!_search)
        return nil;
    MYKeychainItem *item = nil;
    do{
        SecKeychainItemRef found = NULL;
        OSStatus err = SecKeychainSearchCopyNext(_search, &found);
        if (err || !found) {
            if (err != errSecItemNotFound)
                check(err,@"SecKeychainSearchCopyNext");
            CFRelease(_search);
            _search = NULL;
            return nil;
        }
        
        switch (_itemClass) {
            case kSecPrivateKeyItemClass: {
                item = [[MYPrivateKey alloc] initWithKeyRef: (SecKeyRef)found];
                break;
            }
            case kSecCertificateItemClass:
                item = [[MYCertificate alloc] initWithCertificateRef: (SecCertificateRef)found];
                break;
            case kSecPublicKeyItemClass:
                item = [[MYPublicKey alloc] initWithKeyRef: (SecKeyRef)found];
                break;
        }
        CFRelease(found);
    } while (item==nil);
    return item;
}

@end



@implementation MYIdentityEnumerator

- (id) initWithKeychain: (MYKeychain*)keychain keyUsage: (CSSM_KEYUSE)keyUsage {
    self = [super init];
    if (self) {
        if (!check(SecIdentitySearchCreate(keychain.keychainRef, keyUsage, &_searchRef),
                   @"SecIdentitySearchCreate")) {
            return nil;
        }
    }
    return self;
}

- (id) nextObject {
    MYIdentity* identity = nil;
    do {
        SecIdentityRef identityRef = NULL;
        OSStatus err = SecIdentitySearchCopyNext(_searchRef, &identityRef);
        if (err==errKCItemNotFound || !check(err, @"SecIdentitySearchCopyNext"))
            break;
        identity = [[MYIdentity alloc] initWithIdentityRef: identityRef];
    } while (!identity);
    return identity;
}

- (void) dealloc {
    if (_searchRef) CFRelease(_searchRef);
}


@end


#endif //!MYCRYPTO_USE_IPHONE_API



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
