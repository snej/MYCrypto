//
//  MYParsedCertificate.h
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
@class MYCertificate, MYPublicKey, MYPrivateKey, MYOID;

/** A parsed X.509 certificate. Can be used to get more info about an existing cert,
    or to modify a self-signed cert and regenerate it. */
@interface MYParsedCertificate : NSObject 
{
    @private
    NSData *_data;
    NSArray *_root;
    MYCertificate *_issuer;
}

/** Initializes an instance by parsing an existing X.509 certificate's data. */
- (id) initWithCertificateData: (NSData*)data error: (NSError**)outError;

/** The raw data of the certificate. */
@property (readonly) NSData* certificateData;

/** The date/time at which the certificate first becomes valid. */
@property (retain) NSDate *validFrom;

/** The date/time at which the certificate expires. */
@property (retain) NSDate *validTo;

/** The "common name" (nickname, whatever) of the subject/owner of the certificate. */
@property (copy) NSString *commonName;

/** The given/first name of the subject/owner of the certificate. */
@property (copy) NSString *givenName;

/** The surname / last name / family name of the subject/owner of the certificate. */
@property (copy) NSString *surname;

/** A description of the subject/owner of the certificate. */
@property (copy) NSString *description;

/** The raw email address of the subject of the certificate. */
@property (copy) NSString *emailAddress;

/** The public key of the subject of the certificate. */
@property (readonly) MYPublicKey *subjectPublicKey;

/** Returns YES if the issuer is the same as the subject. (Aka a "self-signed" certificate.) */
@property (readonly) BOOL isRoot;

/** Associates the certificate to its issuer.
    If the cert is not self-signed, you must manually set this property before validating. */
@property (retain) MYCertificate* issuer;

/** Checks that the issuer's signature is valid and hasn't been tampered with.
    If the certificate is root/self-signed, the subjectPublicKey is used to check the signature;
    otherwise, the issuer property needs to have been set and its publicKey will be used. */
- (BOOL) validateSignature;


// Generating certificates:

/** Initializes a blank instance which can be used to create a new certificate.
    The certificate will not contain anything yet other than the public key.
    The desired attributes should be set, and then the -selfSignWithPrivateKey:error method called. */
- (id) initWithPublicKey: (MYPublicKey*)pubKey;

/** Has the certificate been signed yet? */
@property (readonly) BOOL isSigned;

/** Signs the certificate using the given private key, which must be the counterpart of the
    public key stored in the certificate.
    The subject attributes will be copied to the issuer attributes.
    If no valid date range has been set yet, it will be set to a range of one year starting from
    the current time.
    A unique serial number based on the current time will be set.
    After this method returns successfully, access the certificateData property to get the
    encoded certificate. */
- (BOOL) selfSignWithPrivateKey: (MYPrivateKey*)privateKey error: (NSError**)outError;

@end
