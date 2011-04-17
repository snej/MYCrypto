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


/** Abstract superclass of test fixtures that respond to some of the same methods as real MYKeys. The intent is that your test cases can create these instead of real keys, and then pass them into your real code as though they were real keys. */
@interface MYMockKey : NSObject
{
    NSData* _keyData;
}

- (id) initWithKeyData: (NSData*)keyData;

@property (nonatomic, readonly) NSData* keyData;

@end


/** A test fixture that responds to some of the same methods as a real MYPublicKey. Currently all it can do is verify data "signed" by its matching MYMockPrivateKey. */
@interface MYMockPublicKey : MYMockKey 

@property (readonly) MYSHA1Digest* publicKeyDigest;

- (BOOL) verifySignature: (NSData*)signature ofData: (NSData*)data;

@end


/** A test fixture that responds to some of the same methods as a real MYPrivateKey. Currently it can only be used to "sign" data. The key internally just consists of a random number, and signing just returns the SHA-1 of the data to be signed appended onto the key. This is of course completely useless cryptographically, but is useful during testing as it avoids the overhead of creating real keys and storing them in the keychain. */
@interface MYMockPrivateKey : MYMockKey 
{
    MYMockPublicKey* _publicKey;
}

/** Creates a random MYMockPrivateKey and its matching MYMockPublicKey. */
+ (MYMockPrivateKey*) createKeyPair;

@property (nonatomic, readonly) MYMockPublicKey* publicKey;
@property (readonly) MYSHA1Digest* publicKeyDigest;

- (NSData*) signData: (NSData*)data;

@end


#endif //DEBUG
