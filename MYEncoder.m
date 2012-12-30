//
//  MYEncoder.m
//  MYCrypto
//
//  Created by Jens Alfke on 1/16/08.
//  Copyright 2008-2009 Jens Alfke. All rights reserved.
//

#import "MYEncoder.h"
#import "MYIdentity.h"
#import "MYCrypto_Private.h"
#import "Test.h"
#import "MYErrorUtils.h"


@implementation MYEncoder


- (id) init
{
    self = [super init];
    if (self != nil) {
        if( ! checksave(CMSEncoderCreate(&_encoder)) ) {
            return nil;
        }
    }
    return self;
}

- (void) dealloc
{
    if(_encoder) CFRelease(_encoder);
}



- (BOOL) addSigner: (MYIdentity*)signer
{
    Assert(signer);
    return checksave( CMSEncoderAddSigners(_encoder, signer.identityRef) );
}

- (BOOL) addRecipient: (MYCertificate*)recipient
{
    Assert(recipient);
    return checksave( CMSEncoderAddRecipients(_encoder, recipient.certificateRef) );
}

- (BOOL) addSupportingCert: (MYCertificate*)supportingCert
{
    Assert(supportingCert);
    return checksave( CMSEncoderAddSupportingCerts(_encoder, supportingCert.certificateRef) );
}

- (BOOL) addTimestamp
{
    return checksave( CMSEncoderAddSignedAttributes(_encoder, kCMSAttrSigningTime) );
}


- (NSError*) error
{
    if( _error )
        return MYError(_error, NSOSStatusErrorDomain, 
                       @"%@", MYErrorName(NSOSStatusErrorDomain,_error));
    else
        return nil;
}


- (CMSCertificateChainMode) certificateChainMode
{
    CMSCertificateChainMode mode;
    if( CMSEncoderGetCertificateChainMode(_encoder, &mode) == noErr )
        return mode;
    else
        return -1;
}

- (void) setCertificateChainMode: (CMSCertificateChainMode)mode
{
    checksave( CMSEncoderSetCertificateChainMode(_encoder, mode) );
}

- (BOOL) hasDetachedContent
{
    Boolean detached;
    return CMSEncoderGetHasDetachedContent(_encoder, &detached)==noErr && detached;
}

- (void) setHasDetachedContent: (BOOL)detached
{
    checksave( CMSEncoderSetHasDetachedContent(_encoder, detached) );
}

- (NSData*) _dataFromFunction: (OSStatus (*)(CMSEncoderRef,CFDataRef*))function
{
    CFDataRef data=NULL;
    if( checksave( (*function)(_encoder, &data) ) )
        return CFBridgingRelease(data);
    else
        return nil;
}


- (CSSM_OID) contentType
{
   NSData *data = [self _dataFromFunction: &CMSEncoderCopyEncapsulatedContentType];
   return (CSSM_OID){data.length,(uint8*)data.bytes};
}

- (void) setContentType: (CSSM_OID)contentType
{
    checksave( CMSEncoderSetEncapsulatedContentType(_encoder, &contentType) );
}


- (BOOL) addData: (NSData*)data
{
    Assert(data);
    return ! _error && checksave( CMSEncoderUpdateContent(_encoder, data.bytes, data.length) );
}


- (NSData*) encodedData
{
    if( ! _error )
        return [self _dataFromFunction: &CMSEncoderCopyEncodedContent];
    else
        return nil;
}


+ (NSData*) encodeData: (NSData*)data
                signer: (MYIdentity*)signer
             recipient: (MYCertificate*)recipient
                 error: (NSError**)outError
{
    MYEncoder *e = [[self alloc] init];
    if( signer )
        [e addSigner: signer];
    if( recipient )
        [e addRecipient: recipient];
    [e addData: data];
    if (outError)
        *outError = e.error;
    return e.encodedData;
}


@end


#if DEBUG

#import "MYCrypto+Cocoa.h"

TestCase(MYEncoder) {
    MYIdentity *me = nil;//[MYIdentity preferredIdentityForName: @"MYCryptoTest"];
    if (!me) {
        NSArray *idents = [[[MYKeychain allKeychains] enumerateIdentities] allObjects];
        SFChooseIdentityPanel *panel = [SFChooseIdentityPanel sharedChooseIdentityPanel];
        [panel setAlternateButtonTitle: @"Cancel"];
        Log(@"Waiting for user to select from choose-identity panel (if you can't see it, move the Xcode window aside!");
        if ([panel my_runModalForIdentities: idents 
                                    message: @"Choose an identity for the MYEncoder test case:"]
                != NSOKButton) {
            [NSException raise: NSGenericException format: @"User canceled"];
        }
        me = [panel my_identity];
        [me makePreferredIdentityForName: @"MYCryptoTest"];
    }
    CAssert(me,@"No default identity has been set up in the Keychain");
    
    NSData *source = [NSData dataWithContentsOfFile: @"/Library/Desktop Pictures/Nature/Ladybug.jpg"];
    if (!source)
        source = [NSData dataWithContentsOfFile: @"/Library/Desktop Pictures/Nature/Zen Garden.jpg"];
    CAssert(source, @"Oops, can't load desktop pic used by MYEncoder test-case");
    
    NSError *error;
    NSData *encoded;
    
    Log(@"Testing signing...");
    encoded = [MYEncoder encodeData: source signer: me recipient: nil error: &error];
    CAssertNil(error);
    CAssert([encoded length]);
    Log(@"MYEncoder signed %lu bytes into %lu bytes", source.length,encoded.length);
    
    Log(@"Testing encryption...");
    encoded = [MYEncoder encodeData: source signer: nil recipient: me error: &error];
    CAssertNil(error);
    CAssert([encoded length]);
    Log(@"MYEncoder encrypted %lu bytes into %lu bytes", source.length,encoded.length);
    
    Log(@"Testing signing+encryption...");
    encoded = [MYEncoder encodeData: source signer: me recipient: me error: &error];
    CAssertNil(error);
    CAssert([encoded length]);
    Log(@"MYEncoder signed/encrypted %lu bytes into %lu bytes", source.length,encoded.length);
}
#endif



/*
 Copyright (c) 2009, Jens Alfke <jens@mooseyard.com>. All rights reserved.
 
 Redistribution and use in source and binary forms, with or without modification, are permitted
 provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice, this list of conditions
 and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 and the following disclaimer in the documentation and/or other materials provided with the
 distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND 
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRI-
 BUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
