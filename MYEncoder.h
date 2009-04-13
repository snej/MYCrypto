//
//  MYEncoder.h
//  MYCrypto
//
//  Created by Jens Alfke on 1/16/08.
//  Copyright 2008-2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/CMSEncoder.h>

@class MYIdentity, MYCertificate;


/** Creates a CMS-formatted message from a blob of data; it can be signed and/or encrypted. */
@interface MYEncoder : NSObject 
{
    @private
    CMSEncoderRef _encoder;
    OSStatus _error;
}

/** A convenience method for one-shot encoding of a block of data.
    @param data  The data that will be signed/encrypted.
    @param signerOrNil  If non-nil, an Identity whose private key will sign the data.
    @param recipientOrNil  If non-nil, the data will be encrypted so only the owner of this
                certificate can read it.
    @param outError  On return, will be set to an NSError if something went wrong.
    @return  The encoded data. */
+ (NSData*) encodeData: (NSData*)data
                signer: (MYIdentity*)signerOrNil
             recipient: (MYCertificate*)recipientOrNil
                 error: (NSError**)outError;

/** Initializes a new encoder.
    You must add at least one signer or recipient. */
- (id) init;

/** Tells the encoder to sign the content with this identity's private key.
    (Multiple signers can be added, but this is rare.) */
- (BOOL) addSigner: (MYIdentity*)signer;

/** Tells the encoder to encrypt the content with this recipient's public key.
    Multiple recipients can be added; any one of them will be able to decrypt the message. */
- (BOOL) addRecipient: (MYCertificate*)recipient;

/** The current error status of the encoder.
    If something goes wrong with an operation, it will return NO,
    and this property will contain the error. */
@property (readonly) NSError* error;

/** Setting this property to YES tells the encoder not to copy the content itself into the
    encoded message. The encodedData property will then contain only metadata, such as
    signatures and certificates.
    This is useful if you're working with a data format that already specifies a content
    format: it allows you to attach the encoded data elsewhere, e.g. in a header or metadata
    attribute. */
@property BOOL hasDetachedContent;

/** Adds data to the encoder. You can add the entire data at once, or in bits and pieces
    (if you're reading it from a stream). */
- (BOOL) addData: (NSData*)data;

/** The signed/encoded output data.
    Don't call this until after the last call to -addData:. */
- (NSData*) encodedData;


/** @name Expert
 *  Advanced methods. 
 */
//@{

/** Adds a timestamp showing when the message was encoded.
    [Unfortunately there is no system API for reading these timestamps in decoded messages...] */
- (BOOL) addTimestamp;

/** Specifies which certificates to include in the message: none, only the signer certs,
    or the signer certs' entire chain (the default). */
@property CMSCertificateChainMode certificateChainMode;

/** Adds an extra certificate to the encoded data, for the recipient's use. Rarely needed. */
- (BOOL) addSupportingCert: (MYCertificate*)supportingCert;

/** The X.509 content type of the message data. */
@property CSSM_OID contentType;

//@}

@end
