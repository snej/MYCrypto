//
//  MYDigest.h
//  MYCrypto
//
//  Created by Jens Alfke on 1/4/08.
//  Copyright 2008 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>


/** Abstract superclass for cryptographic digests (aka hashes).
    Each specific type of digest has its own concrete subclass. */
@interface MYDigest : NSObject <NSCoding, NSCopying>
{
    void *_rawDigest;
}

- (id) initWithRawDigest: (const void*)rawDigest length: (size_t)length;

+ (MYDigest*) digestFromDigestData: (NSData*)digestData;
+ (MYDigest*) digestFromHexString: (NSString*)hexString;

+ (MYDigest*) digestOfData: (NSData*)data;
+ (MYDigest*) digestOfBytes: (const void*)bytes length: (size_t)length;

- (NSComparisonResult) compare: (MYDigest*)other;

@property (readonly) NSData *asData;
@property (readonly) NSString *hexString, *abbreviatedHexString;

@property (readonly) uint32_t /*CSSM_ALGORITHMS*/ algorithm;
@property (readonly) size_t length;
@property (readonly) const void* bytes;

+ (uint32_t /*CSSM_ALGORITHMS*/) algorithm;
+ (size_t) length;

/** Primitive digest generation method; abstract of course. */
+ (void) computeDigest: (void*)dstDigest ofBytes: (const void*)bytes length: (size_t)length;

@end


/** A simple C struct containing a 160-bit SHA-1 digest. */
typedef struct {
    UInt8 bytes[20];
} RawSHA1Digest;
    
/** A 160-bit SHA-1 digest encapsulated in an object. */
@interface MYSHA1Digest : MYDigest

- (MYSHA1Digest*) initWithRawSHA1Digest: (const RawSHA1Digest*)rawDigest;
+ (MYSHA1Digest*) digestFromRawSHA1Digest: (const RawSHA1Digest*)rawDigest;

@property (readonly) const RawSHA1Digest* rawSHA1Digest;

@end


/** A simple C struct containing a 256-bit SHA-256 digest. */
typedef struct {
    UInt8 bytes[32];
} RawSHA256Digest;

/** A 256-bit SHA-256 digest encapsulated in an object. */
@interface MYSHA256Digest : MYDigest

- (MYSHA256Digest*) initWithRawSHA256Digest: (const RawSHA256Digest*)rawDigest;
+ (MYSHA256Digest*) digestFromRawSHA256Digest: (const RawSHA256Digest*)rawDigest;

@property (readonly) const RawSHA256Digest* rawSHA256Digest;

@end


/** Convenience methods for NSData objects */
@interface NSData (MYDigest)
@property (readonly) MYSHA1Digest* my_SHA1Digest;
@property (readonly) MYSHA256Digest* my_SHA256Digest;
@end
