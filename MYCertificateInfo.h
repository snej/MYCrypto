//
//  MYCertificateInfo.h
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
@class MYCertificateName, MYCertificate, MYIdentity, MYPublicKey, MYPrivateKey, MYOID;

/** A parsed X.509 certificate; provides access to the names and metadata. */
@interface MYCertificateInfo : NSObject 
{
    @private
    NSArray *_root;
}

/** Initialize by parsing X.509 certificate data.
    (More commonly you'll get an instance via MYCertificate's 'info' property.) */
- (id) initWithCertificateData: (NSData*)data error: (NSError**)outError;

/** The date/time at which the certificate first becomes valid. */
@property (retain, readonly) NSDate *validFrom;

/** The date/time at which the certificate expires. */
@property (retain, readonly) NSDate *validTo;

/** Information about the identity of the owner of this certificate. */
@property (readonly) MYCertificateName *subject;

/** Information about the identity that signed/authorized this certificate. */
@property (readonly) MYCertificateName *issuer;

/** Returns YES if the issuer is the same as the subject. (Aka a "self-signed" certificate.) */
@property (readonly) BOOL isRoot;

@end



@interface MYCertificateRequest : MYCertificateInfo
{
    @private
    MYPublicKey *_publicKey;
}

/** Initializes a blank instance which can be used to create a new certificate.
    The certificate will not contain anything yet other than the public key.
    The desired attributes should be set, and then the -selfSignWithPrivateKey:error method called. */
- (id) initWithPublicKey: (MYPublicKey*)pubKey;

/** The date/time at which the certificate first becomes valid. Settable. */
@property (retain) NSDate *validFrom;

/** The date/time at which the certificate expires. Settable */
@property (retain) NSDate *validTo;

/** Encodes the certificate request in X.509 format -- this is NOT a certificate!
    It has to be sent to a Certificate Authority to be signed.
    If you want to generate a self-signed certificate, use one of the self-signing methods instead. */
- (NSData*) requestData: (NSError**)outError;

/** Signs the certificate using the given private key, which must be the counterpart of the
    public key stored in the certificate, and returns the encoded certificate data.
    The subject attributes will be copied to the issuer attributes.
    If no valid date range has been set yet, it will be set to a range of one year starting from
    the current time.
    A unique serial number based on the current time will be set. */
- (NSData*) selfSignWithPrivateKey: (MYPrivateKey*)privateKey error: (NSError**)outError;

/** Signs the certificate using the given private key, which must be the counterpart of the
    public key stored in the certificate; adds the certificate to the keychain;
    and returns a MYIdentity representing the paired certificate and private key. */
- (MYIdentity*) createSelfSignedIdentityWithPrivateKey: (MYPrivateKey*)privateKey
                                                 error: (NSError**)outError;
@end



/** An X.509 Name structure, describing the subject or issuer of a certificate.
    The properties are settable only if this instance belongs to a MYCertificateRequest;
    otherwise trying to set them will raise an exception. */
@interface MYCertificateName : NSObject
{
    @private
    NSArray *_components;
}

/** The "common name" (nickname, whatever). */
@property (copy) NSString *commonName;

/** The given/first name. */
@property (copy) NSString *givenName;

/** The surname / last name / family name. */
@property (copy) NSString *surname;

/** A description. */
@property (copy) NSString *nameDescription;

/** The raw email address. */
@property (copy) NSString *emailAddress;

/** Lower-level accessor that returns the value associated with the given OID. */
- (NSString*) stringForOID: (MYOID*)oid;

/** Lower-level accessor that sets the value associated with the given OID. */
- (void) setString: (NSString*)value forOID: (MYOID*)oid;

@end
