//
//  MYDecoder.m
//  Cloudy
//
//  Created by Jens Alfke on 1/16/08.
//  Copyright 2008 Jens Alfke. All rights reserved.
//

#import "MYDecoder.h"
#import "MYCrypto_Private.h"
#import "Test.h"
#import "MYErrorUtils.h"


@interface MYSigner ()
- (id) initWithDecoder: (CMSDecoderRef)decoder index: (size_t)index policy: (CFTypeRef)policy;
@end


@implementation MYDecoder


- (id) initWithData: (NSData*)data error: (NSError**)outError
{
    self = [self init];
    if( self ) {
        [self addData: data];
        [self finish];
        if (outError)
            *outError = self.error;
        if( _error ) {
            [self release];
            return nil;
        }
    }
    return self;
}

- (id) init
{
    self = [super init];
    if (self != nil) {
        OSStatus err = CMSDecoderCreate(&_decoder);
        if( err ) {
            [self release];
            self = nil;
        }
    }
    return self;
}

- (void) dealloc
{
    if( _decoder ) CFRelease(_decoder);
    if (_policy) CFRelease(_policy);
    [super dealloc];
}


- (BOOL) addData: (NSData*)data
{
    Assert(data);
    return !_error && checksave( CMSDecoderUpdateMessage(_decoder, data.bytes, data.length) );
}


- (BOOL) finish
{
    return !_error && checksave( CMSDecoderFinalizeMessage(_decoder) );
}

- (NSError*) error
{
    if( _error )
        return MYError(_error, NSOSStatusErrorDomain, 
                       @"%@", MYErrorName(NSOSStatusErrorDomain,_error));
    else
        return nil;
}

- (BOOL) useKeychain: (MYKeychain*)keychain
{
    return !_error && checksave( CMSDecoderSetSearchKeychain(_decoder, keychain.keychainRef) );
}


- (SecPolicyRef) policy
{
    return _policy;
}

- (void)setPolicy:(SecPolicyRef)policy
{
    if (policy != _policy) {
        if (_policy) CFRelease(_policy);
        if (policy) CFRetain(policy);
        _policy = policy;
    }
}


- (NSData*) _dataFromFunction: (OSStatus (*)(CMSDecoderRef,CFDataRef*))function
{
    CFDataRef data=NULL;
    if( checksave( (*function)(_decoder, &data) ) )
       return [(NSData*)CFMakeCollectable(data) autorelease];
    else
        return nil;
}


- (NSData*) detachedContent
{
    return [self _dataFromFunction: &CMSDecoderCopyDetachedContent];
}

- (void) setDetachedContent: (NSData*)detachedContent
{
    if( ! _error )
        checksave( CMSDecoderSetDetachedContent(_decoder, (CFDataRef)detachedContent) );
}

- (CSSM_OID) contentType
{
    NSData *data = [self _dataFromFunction: &CMSDecoderCopyEncapsulatedContentType];
    return (CSSM_OID){data.length,(uint8*)data.bytes};      // safe since data is autoreleased
}

- (NSData*) content
{
    return [self _dataFromFunction: &CMSDecoderCopyContent];
}

- (BOOL) isSigned
{
    size_t n;
    return checksave( CMSDecoderGetNumSigners(_decoder, &n) ) && n > 0;
}

- (BOOL) isEncrypted
{
    Boolean isEncrypted;
    return check(CMSDecoderIsContentEncrypted(_decoder,&isEncrypted), @"CMSDecoderIsContentEncrypted")
        && isEncrypted;
}

- (NSArray*) signers
{
    size_t n;
    if( ! checksave( CMSDecoderGetNumSigners(_decoder, &n) ) )
        return nil;
    NSMutableArray *signers = [NSMutableArray arrayWithCapacity: n];
    for( size_t i=0; i<n; i++ ) {
        MYSigner *signer = [[MYSigner alloc] initWithDecoder: _decoder
                                                       index: i
                                                      policy: _policy];
        [signers addObject: signer];
        [signer release];
    }
    return signers;
}


- (NSArray*) certificates
{
    CFArrayRef certRefs = NULL;
    if( ! checksave( CMSDecoderCopyAllCerts(_decoder, &certRefs) ) || ! certRefs )
        return nil;
    unsigned n = CFArrayGetCount(certRefs);
    NSMutableArray *certs = [NSMutableArray arrayWithCapacity: n];
    for( unsigned i=0; i<n; i++ ) {
        SecCertificateRef certRef = (SecCertificateRef) CFArrayGetValueAtIndex(certRefs, i);
        [certs addObject: [MYCertificate certificateWithCertificateRef: certRef]];
    }
    CFRelease(certRefs);
    return certs;
}


- (NSString*) dump
{
    static const char * kStatusNames[kCMSSignerInvalidIndex+1] = {
        "kCMSSignerUnsigned", "kCMSSignerValid", "kCMSSignerNeedsDetachedContent",	
        "kCMSSignerInvalidSignature","kCMSSignerInvalidCert","kCMSSignerInvalidIndex"};			
        
    CSSM_OID contentType = self.contentType;
    NSMutableString *s = [NSMutableString stringWithFormat:  @"%@<%p>:\n"
                                                              "\tcontentType = %@ (\"%@\")\n"
                                                              "\tcontent = %u bytes\n"
                                                              "\tsigned=%i, encrypted=%i\n"
                                                              "\tpolicy=%@\n"
                                                              "\t%u certificates\n"
                                                              "\tsigners =\n",
                              self.class, self,
                              OIDAsString(contentType), @"??"/*nameOfOID(&contentType)*/,
                              self.content.length,
                              self.isSigned,self.isEncrypted,
                              MYPolicyGetName(_policy),
                              self.certificates.count];
    for( MYSigner *signer in self.signers ) {
        CMSSignerStatus status = signer.status;
        const char *statusName = (status<=kCMSSignerInvalidIndex) ?kStatusNames[status] :"??";
        [s appendFormat:@"\t\t- status = %s\n"
                         "\t\t  verifyResult = %@\n"
                         "\t\t  trust = %@\n"
                         "\t\t  cert = %@\n",
                 statusName,
                 (signer.verifyResult ?MYErrorName(NSOSStatusErrorDomain,signer.verifyResult)
                                      :@"OK"),
                 MYTrustDescribe(signer.trust),
                 signer.certificate];
    }
    return s;
}


@end



#pragma mark -
@implementation MYSigner : NSObject

#define kUncheckedStatus ((CMSSignerStatus)-1)

- (id) initWithDecoder: (CMSDecoderRef)decoder index: (size_t)index policy: (CFTypeRef)policy
{
    self = [super init];
    if( self ) {
        CFRetain(decoder);
        _decoder = decoder;
        _index = index;
        if(policy) _policy = CFRetain(policy);
        _status = kUncheckedStatus;
    }
    return self;
}

- (void) dealloc
{
    if(_decoder) CFRelease(_decoder);
    if(_policy) CFRelease(_policy);
    if(_trust) CFRelease(_trust);
    [super dealloc];
}

- (void) _getInfo {
    if (_status == kUncheckedStatus) {
        if( !check(CMSDecoderCopySignerStatus(_decoder, _index, _policy, (_policy!=nil),
                                              &_status, &_trust, &_verifyResult), 
                   @"CMSDecoderCopySignerStatus"))
            _status = kMYSignerStatusCheckFailed;
    }
}

- (CMSSignerStatus) status
{
    [self _getInfo];
    return _status;
}

- (OSStatus) verifyResult
{
    [self _getInfo];
    return _verifyResult;
}

- (SecTrustRef) trust
{
    [self _getInfo];
    return _trust;
}


- (NSString*) emailAddress
{
    // Don't let caller see the addr if they haven't checked validity & the signature's invalid:
    if (_status==kUncheckedStatus && self.status != kCMSSignerValid)
        return nil;
    
    CFStringRef email=NULL;
    if( CMSDecoderCopySignerEmailAddress(_decoder, _index, &email) == noErr )
        return [(NSString*)CFMakeCollectable(email) autorelease];
    return nil;
}

- (MYCertificate *) certificate
{
    // Don't let caller see the cert if they haven't checked validity & the signature's invalid:
    if (_status==kUncheckedStatus && self.status != kCMSSignerValid)
        return nil;
    
    SecCertificateRef certRef=NULL;
    OSStatus err = CMSDecoderCopySignerCert(_decoder, _index, &certRef);
    if( err == noErr )
        return [MYCertificate certificateWithCertificateRef: certRef];
    else {
        Warn(@"CMSDecoderCopySignerCert returned err %i",err);
        return nil;
    }
}


- (NSString*) description
{
    NSMutableString *desc = [NSMutableString stringWithFormat: @"%@[st=%i", self.class,(int)self.status];
    int verify = self.verifyResult;
    if( verify )
        [desc appendFormat: @"; verify error %i",verify];
    else {
        MYCertificate *cert = self.certificate;
        if( cert )
            [desc appendFormat: @"; %@",cert.commonName];
    }
    [desc appendString: @"]"];
    return desc;
}


@end




#pragma mark -
#pragma mark TEST CASE:


#if DEBUG

#import "MYEncoder.h"
#import "MYIdentity.h"

static void TestRoundTrip( NSString *title, NSData *source, MYIdentity *signer, MYCertificate *recipient )
{
    Log(@"Testing MYEncoder/Decoder %@...",title);
    NSError *error;
    NSData *encoded = [MYEncoder encodeData: source signer: signer recipient: recipient error: &error];
    CAssertEq(error,nil);
    CAssert([encoded length]);
    Log(@"MYEncoder encoded %u bytes into %u bytes", source.length,encoded.length);
    Log(@"Decoding...");
    MYDecoder *d = [[MYDecoder alloc] init];
    d.policy = [MYCertificate X509Policy];
    [d addData: encoded];
    [d finish];

    CAssertEq(d.error,nil);
    Log(@"%@", d.dump);
    CAssert(d.content);
    CAssert([d.content isEqual: source]);
    CAssertEq(d.detachedContent,nil);
    CAssertEq(d.isSigned,(signer!=nil));
    CAssertEq(d.isEncrypted,(recipient!=nil));

    if( signer ) {
        CAssert(d.certificates.count >= 1);     // may include extra parent certs
        CAssertEq(d.signers.count,1U);
        MYSigner *outSigner = [d.signers objectAtIndex: 0];
        CAssertEq(outSigner.status,(CMSSignerStatus)kCMSSignerValid);
        CAssertEq(outSigner.verifyResult,noErr);
        CAssert([outSigner.certificate isEqualToCertificate: signer]);
    } else {
        CAssertEq(d.certificates.count, 0U);
        CAssertEq(d.signers.count,0U);
    }
    [d release];
}


TestCase(MYDecoder) {
    RequireTestCase(MYEncoder);
    
    MYIdentity *me = [MYIdentity preferredIdentityForName: @"MYCryptoTest"];
    CAssert(me,@"No default identity has been set up in the Keychain");
    Log(@"Using %@", me);
    
    NSData *source = [NSData dataWithContentsOfFile: @"/Library/Desktop Pictures/Nature/Ladybug.jpg"];
    if (!source)
        source = [NSData dataWithContentsOfFile: @"/Library/Desktop Pictures/Nature/Zen Garden.jpg"];
    CAssert(source, @"Oops, can't load desktop pic used by MYDecoder test-case");
    
    TestRoundTrip(@"signing",            source, me,  nil);
    TestRoundTrip(@"encryption",         source, nil, me);
    TestRoundTrip(@"signing+encryption", source, me,  me);
}

#endif DEBUG



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
