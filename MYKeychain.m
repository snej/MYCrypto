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

#if !USE_IPHONE_API


@interface MYKeyEnumerator : NSEnumerator
{
    MYKeychain *_keychain;
    SecKeychainSearchRef _search;
    SecItemClass _itemClass;
}

- (id) initWithKeychain: (MYKeychain*)keychain
              itemClass: (SecItemClass)itemClass
             attributes: (SecKeychainAttribute[])attributes 
                  count: (unsigned)count;
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
        keychain = [[[self alloc] initWithKeychainRef: keychainRef] autorelease];
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
                                 passwordStr ?strlen(passwordStr) :0,
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
    [super dealloc];
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
    return [self retain];
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


#pragma mark -
#pragma mark SEARCHING:


- (MYKeychainItem*) itemOfClass: (SecItemClass)itemClass 
                     withDigest: (MYSHA1Digest*)pubKeyDigest 
{
    SecKeychainAttribute attr = {.tag= (itemClass==kSecCertificateItemClass ?kSecPublicKeyHashItemAttr :kSecKeyLabel), 
                                 .length= pubKeyDigest.length, 
                                 .data= (void*) pubKeyDigest.bytes};
    MYKeyEnumerator *e = [[MYKeyEnumerator alloc] initWithKeychain: self
                                                         itemClass: itemClass
                                                        attributes: &attr count: 1];
    MYKeychainItem *item = e.nextObject;
    [e release];
    return item;
}

- (MYPublicKey*) publicKeyWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return (MYPublicKey*) [self itemOfClass: kSecPublicKeyItemClass withDigest: pubKeyDigest];
}   

- (NSEnumerator*) enumeratePublicKeys {
    return [[[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecPublicKeyItemClass
                                           attributes: NULL count: 0] autorelease];
}

- (NSEnumerator*) publicKeysWithAlias: (NSString*)alias {
    NSData *utf8 = [alias dataUsingEncoding: NSUTF8StringEncoding];
    SecKeychainAttribute attr = {.tag=kSecKeyAlias, .length=utf8.length, .data=(void*)utf8.bytes};
    return [[[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecPublicKeyItemClass
                                           attributes: &attr count: 1] autorelease];
}


- (MYKeyPair*) keyPairWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return (MYKeyPair*) [self itemOfClass: kSecPrivateKeyItemClass withDigest: pubKeyDigest];
}

- (NSEnumerator*) enumerateKeyPairs {
    return [[[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecPrivateKeyItemClass
                                           attributes: NULL count: 0] autorelease];
}

- (MYCertificate*) certificateWithDigest: (MYSHA1Digest*)pubKeyDigest {
    return (MYCertificate*) [self itemOfClass: kSecCertificateItemClass withDigest: pubKeyDigest];
}

- (NSEnumerator*) enumerateCertificates {
    return [[[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecCertificateItemClass
                                           attributes: NULL count: 0] autorelease];
}

- (NSEnumerator*) enumerateSymmetricKeys {
    return [[[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecSymmetricKeyItemClass
                                           attributes: NULL count: 0] autorelease];
}

- (NSEnumerator*) symmetricKeysWithAlias: (NSString*)alias {
    NSData *utf8 = [alias dataUsingEncoding: NSUTF8StringEncoding];
    SecKeychainAttribute attr = {.tag=kSecKeyAlias, .length=utf8.length, .data=(void*)utf8.bytes};
    return [[[MYKeyEnumerator alloc] initWithKeychain: self
                                            itemClass: kSecSymmetricKeyItemClass
                                           attributes: &attr count: 1] autorelease];
}



#pragma mark -
#pragma mark IMPORT:


- (MYPublicKey*) importPublicKey: (NSData*)keyData {
    return [[[MYPublicKey alloc] _initWithKeyData: keyData 
                                      forKeychain: self.keychainRefOrDefault]
            autorelease];
}

- (MYKeyPair*) importPublicKey: (NSData*)pubKeyData 
                    privateKey: (NSData*)privKeyData 
                    alertTitle: (NSString*)title
                   alertPrompt: (NSString*)prompt {
    return [[[MYKeyPair alloc] _initWithPublicKeyData: pubKeyData
                                       privateKeyData: privKeyData
                                          forKeychain: self.keychainRefOrDefault
                                           alertTitle: (NSString*)title
                                          alertPrompt: (NSString*)prompt]
            autorelease];
}

- (MYKeyPair*) importPublicKey: (NSData*)pubKeyData 
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
    MYCertificate *cert = [[[MYCertificate alloc] initWithCertificateData: data 
                                                                    type: type
                                                                encoding: encoding]
                           autorelease];
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


- (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm
{
    return [MYSymmetricKey _generateSymmetricKeyOfSize: keySizeInBits
                                             algorithm: algorithm inKeychain: self];
}

- (MYKeyPair*) generateRSAKeyPairOfSize: (unsigned)keySize {
    return [MYKeyPair _generateRSAKeyPairOfSize: keySize inKeychain: self.keychainRefOrDefault];
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
        _keychain = [keychain retain];
        _itemClass = itemClass;
        SecKeychainAttributeList list = {.count=count, .attr=attributes};
        if (!check(SecKeychainSearchCreateFromAttributes(keychain.keychainRef,
                                                         itemClass,
                                                         &list,
                                                         &_search),
                   @"SecKeychainSearchCreateFromAttributes")) {
            [self release];
            return nil;
        }
    }
    return self;
}

- (void) dealloc
{
    [_keychain release];
    if (_search) CFRelease(_search);
    [super dealloc];
}


- (id) nextObject {
    if (!_search)
        return nil;
    MYPublicKey *key = nil;
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
                MYSHA1Digest *digest = [MYPublicKey _digestOfKey: (SecKeyRef)found];
                if (digest) {
                    MYPublicKey *publicKey = [_keychain publicKeyWithDigest: digest];
                    if (publicKey)
                        key = [[[MYKeyPair alloc] initWithPublicKeyRef: publicKey.keyRef
                                                         privateKeyRef: (SecKeyRef)found]
                               autorelease];
                    else {
                        // The matching public key won't turn up if it's embedded in a certificate;
                        // I'd have to search for certs if I wanted to look that up. Skip it for now.
                        //Warn(@"Couldn't find matching public key for private key! digest=%@",digest);
                    }
                }
                break;
            }
            case kSecCertificateItemClass:
                key = [[[MYCertificate alloc] initWithCertificateRef: (SecCertificateRef)found] autorelease];
                break;
            case kSecPublicKeyItemClass:
                key = [[[MYPublicKey alloc] initWithKeyRef: (SecKeyRef)found] autorelease];
                break;
        }
        CFRelease(found);
    } while (key==nil);
    return key;
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