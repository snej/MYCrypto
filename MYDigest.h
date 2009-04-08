//
//  MYDigest.h
//  MYCrypto
//
//  Created by Jens Alfke on 1/4/08.
//  Copyright 2008 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>


/** Abstract superclass for cryptographic digests (aka hashes).
    Each specific type of digest has its own concrete subclass.
    Digests are full-fledged value objects, and can be compared, used as dictionary keys,
    copied, and archived. */
@interface MYDigest : NSObject <NSCoding, NSCopying>
{
    @private
    void *_rawDigest;
}

/** Initializes a MYDigest from an existing raw digest.
    MYDigest itself is abstract, so this must be called on a subclass instance. */
- (id) initWithRawDigest: (const void*)rawDigest length: (size_t)length;

/** Wraps an existing digest, stored in an NSData object, in a MYDigest object. */
+ (MYDigest*) digestFromDigestData: (NSData*)digestData;

/** Wraps an existing digest, expressed as a hex string, in a MYDigest object. */
+ (MYDigest*) digestFromHexString: (NSString*)hexString;

/** Computes a cryptographic digest of the given data. */
+ (MYDigest*) digestOfData: (NSData*)data;

/** Computes a cryptographic digest of the given data. */
+ (MYDigest*) digestOfBytes: (const void*)bytes length: (size_t)length;

/** Returns the digest as an NSData object. */
@property (readonly) NSData *asData;

/** Returns the digest as a hex string. */
@property (readonly) NSString *hexString;

/** Returns the first 8 digits (32 bits) of the digest's hex string, followed by "...".
    This is intended only for use in log messages or object descriptions, since
    32 bits isn't nearly enough to provide any useful uniqueness. */
@property (readonly) NSString *abbreviatedHexString;

/** The algorithm that created this digest. 
    Values are defined in the CSSM_ALGORITHMS enum in cssmtype.h.
    (Abstract method.) */
@property (readonly) uint32_t algorithm;

/** The length (in bytes, not bits!) of this digest. */
@property (readonly) size_t length;

/** A pointer to the raw bytes of digest data. */
@property (readonly) const void* bytes;

/** The algorithm used by this subclass. (Abstract method.) */
+ (uint32_t) algorithm;

/** The length of digests created by this subclass. (Abstract method.) */
+ (size_t) length;

/** Primitive digest generation method. (Abstract.) */
+ (void) computeDigest: (void*)dstDigest ofBytes: (const void*)bytes length: (size_t)length;

@end


// A simple C struct containing a 160-bit SHA-1 digest. Used by the MYSHA1Digest class.
typedef struct {
    UInt8 bytes[20];
} RawSHA1Digest;
    
/** A 160-bit SHA-1 digest encapsulated in an object. */
@interface MYSHA1Digest : MYDigest
{ }

/** Initialize a MYSHA1Digest object given an existing raw SHA-1 digest. */
- (MYSHA1Digest*) initWithRawSHA1Digest: (const RawSHA1Digest*)rawDigest;

/** Create a MYSHA1Digest object given an existing raw SHA-1 digest. */
+ (MYSHA1Digest*) digestFromRawSHA1Digest: (const RawSHA1Digest*)rawDigest;

/** The SHA-1 digest as a C struct */
@property (readonly) const RawSHA1Digest* rawSHA1Digest;

@end


// A simple C struct containing a 256-bit SHA-256 digest.
typedef struct {
    UInt8 bytes[32];
} RawSHA256Digest;

/** A 256-bit SHA-256 digest encapsulated in an object. Used by the MYSHA256Digest class. */
@interface MYSHA256Digest : MYDigest
{ }

/** Initialize a MYSHA256Digest object given an existing raw SHA-1 digest. */
- (MYSHA256Digest*) initWithRawSHA256Digest: (const RawSHA256Digest*)rawDigest;

/** Create a MYSHA256Digest object given an existing raw SHA-1 digest. */
+ (MYSHA256Digest*) digestFromRawSHA256Digest: (const RawSHA256Digest*)rawDigest;

/** The SHA-256 digest as a C struct */
@property (readonly) const RawSHA256Digest* rawSHA256Digest;

@end


/** Convenience methods for computing digests of NSData objects. */
@interface NSData (MYDigest)

/** The SHA-1 digest of the receiver's data. */
@property (readonly) MYSHA1Digest* my_SHA1Digest;

/** The SHA-256 digest of the receiver's data. */
@property (readonly) MYSHA256Digest* my_SHA256Digest;

@end
