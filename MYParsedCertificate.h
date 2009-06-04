//
//  MYParsedCertificate.h
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
@class MYCertificate, MYOID;

/** A parsed X.509 certificate. Can be used to get more info about an existing cert,
    or to modify a self-signed cert and regenerate it. */
@interface MYParsedCertificate : NSObject 
{
    NSData *_data;
    id _root;
    MYCertificate *_issuer;
}

+ (MYOID*) RSAWithSHA1AlgorithmID;

- (id) initWithCertificateData: (NSData*)data error: (NSError**)outError;

/** Associates the certificate to its issuer.
    If the cert is not self-signed, you must manually set this property before verifying. */
@property (retain) MYCertificate* issuer;

@end
