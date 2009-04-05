//
//  MYPublicKey-iPhone.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYPublicKey.h"
#import "MYCrypto_Private.h"

#if USE_IPHONE_API

#import "MYDigest.h"
#import "MYErrorUtils.h"


@implementation MYPublicKey


- (void) dealloc
{
    [_digest release];
    [super dealloc];
}


- (SecExternalItemType) keyType {
    return kSecAttrKeyClassPublic;
}


- (MYPublicKey*) asPublicKey {
    return self;
}



- (MYSHA1Digest*) publicKeyDigest {
    NSData *digestData = [self _attribute: kSecAttrApplicationLabel];
    if (digestData)
        return (MYSHA1Digest*) [MYSHA1Digest digestFromDigestData: digestData];
    else {
        Warn(@"MYKeyPair: public key didn't have digest attribute");
        return nil;
    }
}


- (NSData*) encryptData: (NSData*)data {
    return _crypt(self.keyRef,data,kCCEncrypt);
}


- (BOOL) verifySignature: (NSData*)signature ofData: (NSData*)data {
    Assert(data);
    Assert(signature);
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes,data.length, digest);
    OSStatus err = SecKeyRawVerify(self.keyRef, kSecPaddingPKCS1SHA1,
                                   digest,sizeof(digest), //data.bytes, data.length,
                                   signature.bytes, signature.length);
    return err==noErr;
}


@end




NSData* _crypt(SecKeyRef key, NSData *data, CCOperation op) {
    CAssert(data);
    size_t dataLength = data.length;
    size_t outputLength = MAX(dataLength, SecKeyGetBlockSize(key));
    void *outputBuf = malloc(outputLength);
    if (!outputBuf) return nil;
    OSStatus err;
    if (op==kCCEncrypt)
        err = SecKeyEncrypt(key, kSecPaddingNone,//PKCS1, 
                            data.bytes, dataLength,
                            outputBuf, &outputLength);
    else
        err = SecKeyDecrypt(key, kSecPaddingNone,//PKCS1, 
                            data.bytes, dataLength,
                            outputBuf, &outputLength);
    if (err) {
        free(outputBuf);
        Warn(@"%scrypting failed (%i)", (op==kCCEncrypt ?"En" :"De"), err);
        // Note: One of the errors I've seen is -9809, which is errSSLCrypto (SecureTransport.h)
        return nil;
    } else
        return [NSData dataWithBytesNoCopy: outputBuf length: outputLength freeWhenDone: YES];
}

#endif USE_IPHONE_API
