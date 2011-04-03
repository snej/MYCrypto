//
//  MYCertificateInfo.h
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
@class MYCertificateName, MYCertificateExtensions, MYCertificate, MYIdentity, MYPublicKey, MYPrivateKey, MYOID;

/** A parsed X.509 certificate; provides access to the names and metadata. */
@interface MYCertificateInfo : NSObject 
{
    @private
    NSArray *_root;
    NSData *_data;
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

@property (readonly) MYCertificateExtensions* extensions;

/** Returns YES if the issuer is the same as the subject. (Aka a "self-signed" certificate.) */
@property (readonly) BOOL isRoot;

/** Verifies the certificate's signature, using the given public key.
    If the certificate is root/self-signed, use the cert's own subject public key. */
- (BOOL) verifySignatureWithKey: (MYPublicKey*)issuerPublicKey;

@end



/** A mutable, unsigned certificate that can be filled out and then signed by the issuer.
    Used to generate an identity certificate for a key-pair. */
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



/** An X.509 Extensions structure, describing optional extensions in a certificate.
    The properties are settable only if this instance belongs to a MYCertificateRequest;
    otherwise trying to set them will raise an exception. */
@interface MYCertificateExtensions : NSObject
{
    @private
    NSArray *_extensions;
}

@property (readonly) NSArray* extensionOIDs;

- (id) extensionForOID: (MYOID*)oid isCritical: (BOOL*)outIsCritical;

- (void) setExtension: (id)extension isCritical: (BOOL)isCritical forOID: (MYOID*)oid;

@property UInt16 keyUsage;

/** Checks whether the given key usage(s) are allowed by the certificate signer.
    Returns NO if the KeyUsage extension is present, and marked critical, and does not include
    all of the requested usages.
    @param keyUsage  One or more kKeyUsage flags, OR'ed together. */
- (BOOL) allowsKeyUsage: (UInt16)keyUsage;

@property (copy) NSSet* extendedKeyUsage;

/** Checks whether the given extended key usage(s) are allowed by the certificate signer.
    Returns NO if the ExtendedKeyUsage extension is present, and marked critical,
    and does not include all of the requested usages.
    @param extendedKeyUsage  A set of kExtendedKeyUsage OIDs. */
- (BOOL) allowsExtendedKeyUsage: (NSSet*) extendedKeyUsage;

@end


extern MYOID *kKeyUsageOID, *kExtendedKeyUsageOID;

enum {
    kKeyUsageDigitalSignature   = 0x80,
    kKeyUsageNonRepudiation     = 0x40,
    kKeyUsageKeyEncipherment    = 0x20,
    kKeyUsageDataEncipherment   = 0x10,
    kKeyUsageKeyAgreement       = 0x08,
    kKeyUsageKeyCertSign        = 0x04,
    kKeyUsageCRLSign            = 0x02,
    kKeyUsageEncipherOnly       = 0x01,
    kKeyUsageDecipherOnly       = 0x100,
    kKeyUsageUnspecified        = 0xFFFF        // Returned if key-usage extension is not present
};

/** These are the constants that can appear in the extendedKeyUsage set. */
extern MYOID *kExtendedKeyUsageServerAuthOID, *kExtendedKeyUsageClientAuthOID,
             *kExtendedKeyUsageCodeSigningOID, *kExtendedKeyUsageEmailProtectionOID;
