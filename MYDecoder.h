//
//  MYDecoder.h
//  MYCrypto
//
//  Created by Jens Alfke on 1/16/08.
//  Copyright 2008 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/CMSDecoder.h>

@class MYKeychain, MYCertificate;


/** Decodes a CMS-formatted message into the original data, and identifies & verifies signatures. */
@interface MYDecoder : NSObject 
{
    @private
    CMSDecoderRef _decoder;
    OSStatus _error;
    SecPolicyRef _policy;
}

/** Initializes a new decoder. */
- (id) init;

/** Initializes a new decoder and reads the entire message data. */
- (id) initWithData: (NSData*)data error: (NSError**)outError;

/** Specifies a keychain to use to look up certificates and keys, instead of the default
    keychain search path. */
- (BOOL) useKeychain: (MYKeychain*)keychain;

/** Adds data to the decoder. You can add the entire data at once, or in bits and pieces
    (if you're reading it from a stream). */
- (BOOL) addData: (NSData*)data;

/** The error, if any, that occurred while decoding the content.
    If -addData: returns NO, read this property to find out what went wrong.
    The most likely error is (NSOSStatusErrorDomain, errSecUnknownFormat). */
@property (readonly) NSError *error;

/** If the message content is detached (stored separately from the encoded message),
    you must copy it to this property before calling -finish, so that the decoder can use it
    to verify signatures. */
@property (retain) NSData *detachedContent;

/** Tells the decoder that all of the data has been read, after the last call to -addData:. 
    You must call this before accessing the message content or metadata. */
- (BOOL) finish;

/** The decoded message content. */
@property (readonly) NSData* content;

/** YES if the message was signed. (Use the signers property to see who signed it.) */
@property (readonly) BOOL isSigned;

/** YES if the message was encrypted. */
@property (readonly) BOOL isEncrypted;

/** An array of MYSigner objects representing the identities who signed the message.
    Nil if the message is unsigned. */
@property (readonly) NSArray* signers;
 
/** All of the certificates (as MYCertificate objects) that were attached to the message. */
@property (readonly) NSArray* certificates;


/** @name Expert
 *  Advanced methods. 
 */
//@{

/** The X.509 content-type of the message contents.
    The Data field points to autoreleased memory: do not free it yourself, and do not
    expect it to remain valid after the calling method returns. */
@property (readonly) CSSM_OID contentType;

/** The Policy that will be used to evaluate trust when calling MYSigner.copyTrust.
    NULL by default. */
@property (assign) SecPolicyRef policy;

/** Returns a string with detailed information about the message metadata.
    Not user-presentable; used for debugging. */
- (NSString*) dump;

//@}

@end


/** Represents a signer of a CMS message, as returned by the MYDecoder.signers property. */
@interface MYSigner : NSObject
{
    @private
    CMSDecoderRef _decoder;
    size_t _index;
    CFTypeRef _policy;
    CMSSignerStatus _status;
    OSStatus _verifyResult;
    SecTrustRef _trust;
}

/** The status of the signature, i.e. whether it's valid or not.
 *  Values include:
 *	  kCMSSignerValid               :both signature and signer certificate verified OK.
 *	  kCMSSignerNeedsDetachedContent:the MYDecoder's detachedContent property must be set,
 *                                   to ascertain the signature status.
 *	  kCMSSignerInvalidSignature    :bad signature -- either the content or the signature
 *                                   data were tampered with after the message was encoded.
 *	  kCMSSignerInvalidCert         :an error occurred verifying the signer's certificate.
 *							         Further information available via the verifyResult
 *                                   and copyTrust methods.
 */
@property (readonly) CMSSignerStatus status;

/** The signer's certificate.
    You should check the status property first, to see whether the signature and certificate
    are valid.
    For safety purposes, if you haven't checked status yet, this method will return nil
    if the signer status is not kCMSSignerValid. */
@property (readonly) MYCertificate *certificate;

/** The signer's email address (if any), as stored in the certificate. */
@property (readonly) NSString* emailAddress;

/** @name Expert
 *  Advanced methods. 
 */
//@{

/** Returns the SecTrustRef that was used to verify the certificate.
    You can use this object to get more detailed information about how the verification was done.
    If you set the parent decoder's policy property, then that SecPolicy will be used to evaluate
    trust; otherwise you'll need to do it yourself using the SecTrust object. */
@property (readonly) SecTrustRef trust;

/** The result of certificate verification, as a CSSM_RESULT code; 
 *  a nonzero value indicates an error.
 *
 * Some of the most common and interesting errors are:
 *
 * CSSMERR_TP_INVALID_ANCHOR_CERT : The cert was verified back to a 
 *		self-signed (root) cert which was present in the message, but 
 *		that root cert is not a known, trusted root cert. 
 * CSSMERR_TP_NOT_TRUSTED: The cert could not be verified back to 
 *		a root cert.
 * CSSMERR_TP_VERIFICATION_FAILURE: A root cert was found which does
 *   	not self-verify. 
 * CSSMERR_TP_VERIFY_ACTION_FAILED: Indicates a failure of the requested 
 *		policy action. 
 * CSSMERR_TP_INVALID_CERTIFICATE: Indicates a bad leaf cert. 
 * CSSMERR_TP_CERT_EXPIRED: A cert in the chain was expired at the time of
 *		verification.
 * CSSMERR_TP_CERT_NOT_VALID_YET: A cert in the chain was not yet valie at 
 *		the time of	verification.
 */
@property (readonly) OSStatus verifyResult;

//@}

@end


enum {
    /** Returned from MYSigner.status to indicate a failure (non-noErr return value)
     of the underlying CMSDecoderCopySignerStatus call. Should never occur. */
    kMYSignerStatusCheckFailed = 666
};
