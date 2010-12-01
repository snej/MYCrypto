//
//  MYMockKeys.m
//  MYCrypto
//
//  Created by Jens Alfke on 11/25/10.
//  Copyright 2010 Jens Alfke. All rights reserved.
//

#import "MYMockKeys.h"
#import "Test.h"
#import "MYDigest.h"


#if DEBUG


@implementation MYMockKey


@synthesize keyData=_keyData;


- (id) initWithKeyData: (NSData*)keyData {
    Assert(keyData);
    self = [super init];
    if (self != nil) {
        _keyData = [keyData copy];
    }
    return self;
}


- (void) dealloc
{
    [_keyData release];
    [super dealloc];
}


- (NSString*) description {
    NSString* keyStr = [[NSString alloc] initWithData: _keyData encoding: NSUTF8StringEncoding];
    return $sprintf(@"%@[%@]", [self class], keyStr);
    [keyStr release];
}


@end



@implementation MYMockPrivateKey


@synthesize publicKey=_publicKey;


+ (MYMockPrivateKey*) createKeyPair {
    return [[[MYMockPrivateKey alloc] init] autorelease];
}


- (id) initWithKeyData: (NSData*)keyData {
    self = [super initWithKeyData:keyData];
    if (self != nil) {
        _publicKey = [[MYMockPublicKey alloc] initWithKeyData:_keyData];
    }
    return self;
}


- (id) init
{
    NSString *key = [NSString stringWithFormat: @"MOCK_%08X:", random()];
    return [self initWithKeyData: [key dataUsingEncoding:NSUTF8StringEncoding]];
}


- (void) dealloc
{
    [_publicKey release];
    [super dealloc];
}


- (MYSHA1Digest*) publicKeyDigest {
    return _publicKey.publicKeyDigest;
}


- (NSData*) signData: (NSData*)data {
    Assert(data);
    const RawSHA1Digest *digest = [[MYSHA1Digest digestOfData:data] rawSHA1Digest];
    NSMutableData* result = [NSMutableData dataWithData: _keyData];
    [result appendBytes: digest length: sizeof(*digest)];
    return result;
}


@end




@implementation MYMockPublicKey


- (MYSHA1Digest*) publicKeyDigest {
    return _keyData.my_SHA1Digest;
}


- (BOOL) verifySignature: (NSData*)signature ofData: (NSData*)data {
    Assert(data);
    const RawSHA1Digest *digest = [[MYSHA1Digest digestOfData:data] rawSHA1Digest];
    size_t keyLength = _keyData.length;
    if (signature.length != keyLength + sizeof(*digest))
        return NO;
    if (memcmp(signature.bytes, _keyData.bytes, keyLength) != 0)
        return NO;
    if (memcmp(signature.bytes + keyLength, digest, sizeof(*digest) - keyLength) != 0)
        return NO;
    return YES;
}


@end




TestCase(MYMockPrivateKey) {
    MYMockPrivateKey* privateKey = [MYMockPrivateKey createKeyPair];
    MYMockPublicKey* publicKey = privateKey.publicKey;
    Log(@"privateKey = %@; publicKey = %@", privateKey, publicKey);
    NSData *pubKeyData = publicKey.keyData;
    CAssertEq(pubKeyData.length, 14u);
    CAssertEqual(privateKey.keyData, pubKeyData);
    
    MYSHA1Digest *pubKeyDigest = publicKey.publicKeyDigest;
    Log(@"Public key digest = %@",pubKeyDigest);
    CAssertEqual(privateKey.publicKeyDigest, pubKeyDigest);
    
    // Let's sign data:
    NSData *data = [@"This is a test. This is only a test!" dataUsingEncoding: NSUTF8StringEncoding];
    NSData *sig = [privateKey signData: data];
    Log(@"Signature = %@ (%u bytes)",sig,sig.length);
    CAssert(sig);
    CAssert( [publicKey verifySignature: sig ofData: data] );    

    // Test creating a public key from data:
    Log(@"Reconstituting public key from data...");
    MYMockPublicKey* pub = [[MYMockPublicKey alloc] initWithKeyData: pubKeyData];
    CAssert(pub);
    CAssertEqual(pub.keyData, pubKeyData);
    CAssertEqual(pub.publicKeyDigest, pubKeyDigest);
    CAssert( [pub verifySignature: sig ofData: data] );
    [pub release];
    Log(@"Verified signature from reconstituted key.");
}

#endif DEBUG
