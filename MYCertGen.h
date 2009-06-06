//
//  MYCertGen.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/3/09.
//  Copyright 2009 Jens Alfke. All rights reserved.

//  NOTE: This module has been replaced by MYCertificateInfo, which isn't dependent on
//  CSSM APIs that aren't available on iPhone.

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class MYPublicKey, MYPrivateKey, MYCertificate, MYIdentity;


NSData* MYCertificateCreateTemplate(const CSSM_X509_NAME *subject, const CSSM_X509_NAME *issuer,
                                    NSDate *validFrom, NSDate *validTo,
                                    uint32_t serialNumber,
                                    const CSSM_X509_EXTENSION **extensions, unsigned nExtensions,
                                    MYPublicKey *publicKey,
                                    const CSSM_X509_ALGORITHM_IDENTIFIER *signingAlgorithm,
                                    CSSM_CL_HANDLE clHandle);

NSData* MYCertificateSign(NSData *certificateTemplate, 
                          MYPrivateKey *privateKey, 
                          CSSM_ALGORITHMS signingAlgorithmID,
                          CSSM_CL_HANDLE cssmCLHandle);

MYCertificate *createCertificate(const CSSM_X509_NAME *subject, const CSSM_X509_NAME *issuer,
                                 NSDate *validFrom, NSDate *validTo,
                                 uint32_t serialNumber,
                                 const CSSM_X509_EXTENSION **extensions, unsigned nExtensions,
                                 MYPrivateKey *privateKey, 
                                 const CSSM_X509_ALGORITHM_IDENTIFIER *signingAlgorithm,
                                 CSSM_ALGORITHMS signingAlgorithmID,
                                 CSSM_CL_HANDLE cssmCLHandle);

CSSM_CL_HANDLE getCLHandle();


MYCertificate* MYCertificateCreateSelfSigned(MYPrivateKey *privateKey,
                                             NSDictionary *attributes );
MYIdentity* MYIdentityCreateSelfSigned(MYPrivateKey *privateKey,
                                       NSDictionary *attributes );
