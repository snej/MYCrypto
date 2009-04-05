//
//  MYSymmetricKey.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKey.h"
#import <CommonCrypto/CommonCryptor.h>


@interface MYSymmetricKey : MYKey <MYEncryption, MYDecryption>

/** Initializes a symmetric key from the given key data and algorithm. */
- (id) initWithKeyData: (NSData*)keyData
             algorithm: (CCAlgorithm)algorithm;

/** Randomly generates a new symmetric key, using the given algorithm and key-size in bits.
    The key is not added to any keychain; if you want to keep the key persistently, use
    the method of the same name in the MYKeychain class. */
+ (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm;

/** The key's algorithm. */
@property (readonly) CCAlgorithm algorithm;

@end
