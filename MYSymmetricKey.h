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

+ (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm;

@property (readonly) CCAlgorithm algorithm;

@end
