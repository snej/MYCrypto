//
//  MYCrypto_Private.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/23/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeychain.h"
#import "MYKey.h"
#import "MYSymmetricKey.h"
#import "MYKeyPair.h"
#import "MYCertificate.h"
#import "Test.h"
#import <Security/Security.h>

/*  The iPhone simulator actually has the Mac OS X security API, not the iPhone one.
    So don't use the iPhone API when configured to run in the simulator. */
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
#define USE_IPHONE_API 1
#else
#define USE_IPHONE_API 0
#endif

#if USE_IPHONE_API
typedef CFTypeRef SecKeychainAttrType;
typedef CFTypeRef SecKeychainItemRef;
typedef CFTypeRef SecKeychainRef;
typedef CFTypeRef SecExternalItemType;
#endif


#if TARGET_IPHONE_SIMULATOR
@interface MYKeychain (Private)
- (id) initWithKeychainRef: (SecKeychainRef)keychainRef;
@property (readonly) SecKeychainRef keychainRef, keychainRefOrDefault;
@property (readonly) CSSM_CSP_HANDLE CSPHandle;
@property (readonly) NSString* path;
@end
#endif


@interface MYKeychainItem (Private);
- (id) initWithKeychainItemRef: (MYKeychainItemRef)itemRef;
- (NSData*) _getContents: (OSStatus*)outError;
- (NSString*) stringValueOfAttribute: (SecKeychainAttrType)attr;
- (BOOL) setValue: (NSString*)valueStr ofAttribute: (SecKeychainAttrType)attr;
+ (NSData*) _getAttribute: (SecKeychainAttrType)attr ofItem: (MYKeychainItemRef)item;
- (id) _attribute: (SecKeychainAttrType)attribute;
+ (NSString*) _getStringAttribute: (SecKeychainAttrType)attr ofItem: (MYKeychainItemRef)item;
+ (BOOL) _setAttribute: (SecKeychainAttrType)attr ofItem: (MYKeychainItemRef)item
           stringValue: (NSString*)stringValue;
@end      


@interface MYKey (Private)
- (id) initWithKeyData: (NSData*)data;
- (id) _initWithKeyData: (NSData*)data
            forKeychain: (SecKeychainRef)keychain;
@property (readonly) SecExternalItemType keyType;
#if !USE_IPHONE_API
@property (readonly) const CSSM_KEY* cssmKey;
- (NSData*) exportKeyInFormat: (SecExternalFormat)format withPEM: (BOOL)withPEM;
#endif
@property (readonly) NSArray* _itemList;
@end


@interface MYSymmetricKey (Private)
+ (MYSymmetricKey*) _generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                      algorithm: (CCAlgorithm)algorithm
                                     inKeychain: (MYKeychain*)keychain;
@end


@interface MYPublicKey (Private)
+ (MYSHA1Digest*) _digestOfKey: (SecKeyRef)key;
- (BOOL) setValue: (NSString*)valueStr ofAttribute: (SecKeychainAttrType)attr;
@end


@interface MYKeyPair (Private)
+ (MYKeyPair*) _generateRSAKeyPairOfSize: (unsigned)keySize
                            inKeychain: (SecKeychainRef)keychain;
- (id) _initWithPublicKeyData: (NSData*)pubKeyData 
               privateKeyData: (NSData*)privKeyData
                  forKeychain: (SecKeychainRef)keychain
                   alertTitle: (NSString*)title
                  alertPrompt: (NSString*)prompt;
- (id) _initWithPublicKeyData: (NSData*)pubKeyData 
               privateKeyData: (NSData*)privKeyData
                  forKeychain: (SecKeychainRef)keychain 
                   passphrase: (NSString*)passphrase;
#if !TARGET_OS_IPHONE
- (NSData*) _exportPrivateKeyInFormat: (SecExternalFormat)format
                              withPEM: (BOOL)withPEM
                           passphrase: (NSString*)passphrase;
#endif
@end


#if TARGET_IPHONE_SIMULATOR
@interface MYCertificate (Private)
- (id) initWithCertificateData: (NSData*)data
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding;
@end
#endif


NSData* _crypt(SecKeyRef key, NSData *data, CCOperation op);

#undef check
BOOL check(OSStatus err, NSString *what);

#if !USE_IPHONE_API
BOOL checkcssm(CSSM_RETURN err, NSString *what);

SecKeyRef importKey(NSData *data, 
                    SecExternalItemType type,
                    SecKeychainRef keychain,
                    SecKeyImportExportParameters *params /*non-null*/);
CSSM_CC_HANDLE cssmCreateSignatureContext(SecKeyRef key);
#endif
