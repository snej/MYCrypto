//
//  MYMockKeys.h
//  MYCrypto
//
//  Created by Jens Alfke on 11/25/10.
//  Copyright 2010 Jens Alfke. All rights reserved.
//

#import "MYPublicKey.h"
#import "MYPrivateKey.h"
@class MYSHA1Digest;

#if DEBUG


@interface MYMockKey : NSObject
{
    NSData* _keyData;
}

- (id) initWithKeyData: (NSData*)keyData;

@property (nonatomic, readonly) NSData* keyData;

@end


@interface MYMockPublicKey : MYMockKey 

@property (readonly) MYSHA1Digest* publicKeyDigest;

- (BOOL) verifySignature: (NSData*)signature ofData: (NSData*)data;

@end


@interface MYMockPrivateKey : MYMockKey 
{
    MYMockPublicKey* _publicKey;
}

+ (MYMockPrivateKey*) createKeyPair;

@property (nonatomic, readonly) MYMockPublicKey* publicKey;
@property (readonly) MYSHA1Digest* publicKeyDigest;

- (NSData*) signData: (NSData*)data;

@end


#endif //DEBUG
