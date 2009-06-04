//
//  MYParsedCertificate.m
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

// References:
// <http://en.wikipedia.org/wiki/X.509>
// <http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt>


#import "MYParsedCertificate.h"
#import "MYASN1Object.h"
#import "MYOID.h"
#import "MYBERParser.h"
#import "MYDEREncoder.h"
#import "MYPublicKey.h"
#import "MYCertificate.h"
#import "MYErrorUtils.h"


static id $atIf(NSArray *array, NSUInteger index) {
    return index < array.count ?[array objectAtIndex: index] :nil;
}


@implementation MYParsedCertificate


static MYOID *kRSAAlgorithmID, *kRSAWithSHA1AlgorithmID;


+ (void) initialize {
    if (!kRSAAlgorithmID) {
        UInt32 components[7] = {1, 2, 840, 113549, 1, 1, 1,};
        kRSAAlgorithmID = [[MYOID alloc] initWithComponents: components count: 7];
    }
    if (!kRSAWithSHA1AlgorithmID) {
        UInt32 components[7] = {1, 2, 840, 113549, 1, 1, 5};
        kRSAWithSHA1AlgorithmID = [[MYOID alloc] initWithComponents: components count: 7];
    }
}

+ (MYOID*) RSAAlgorithmID           {return kRSAAlgorithmID;}
+ (MYOID*) RSAWithSHA1AlgorithmID   {return kRSAWithSHA1AlgorithmID;}


+ (NSString*) validate: (id)root {
    NSArray *top = $castIf(NSArray,root);
    if (top.count < 3)
        return @"Too few top-level components";
    NSArray *info = $castIf(NSArray, [top objectAtIndex: 0]);
    if (info.count < 7)
        return @"Too few identity components";
    MYASN1Object *version = $castIf(MYASN1Object, [info objectAtIndex: 0]);
    if (!version || version.tag != 0)
        return @"Missing or invalid version";
    NSArray *versionComps = $castIf(NSArray, version.components);
    if (!versionComps || versionComps.count != 1)
        return @"Invalid version";
    NSNumber *versionNum = $castIf(NSNumber, [versionComps objectAtIndex: 0]);
    if (!versionNum || versionNum.intValue < 0 || versionNum.intValue > 2)
        return @"Unrecognized version number";
    return nil;
}


- (id) initWithCertificateData: (NSData*)data error: (NSError**)outError;
{
    self = [super init];
    if (self != nil) {
        if (outError) *outError = nil;
        id root = MYBERParse(data,outError);
        NSString *errorMsg = [[self class] validate: root];
        if (errorMsg) {
            if (!*outError)
                *outError = MYError(2, MYASN1ErrorDomain, @"Invalid certificate: %@", errorMsg);
            [self release];
            return nil;
        }
        _root = [root retain];
        _data = [data copy];
    }
    return self;
}

- (void) dealloc
{
    
    [_root release];
    [_issuer release];
    [super dealloc];
}


@synthesize issuer=_issuer;


- (NSArray*) info    {return $castIf(NSArray,$atIf(_root,0));}

- (BOOL) isSelfSigned {
    id issuer  = $atIf(self.info,3);
    id subject = $atIf(self.info,5);
    return $equal(issuer,subject);
}

- (MYPublicKey*) subjectPublicKey {
    NSArray *keyInfo = $cast(NSArray, $atIf(self.info, 6));
    MYOID *keyAlgorithmID = $castIf(MYOID, $atIf($castIf(NSArray,$atIf(keyInfo,0)), 0));
    if (!$equal(keyAlgorithmID, kRSAAlgorithmID))
        return nil;
    MYBitString *keyData = $cast(MYBitString, $atIf(keyInfo, 1));
    if (!keyData) return nil;
    return [[[MYPublicKey alloc] initWithKeyData: keyData.bits] autorelease];
    /*
    NSArray *keyParts = $castIf(NSArray, MYBERParse(keyData, nil));
    if (!keyParts) return nil;
    MYBitString *modulus = $castIf(MYBitString, $atIf(keyParts,0));
    int exponent = [$castIf(NSNumber, $atIf(keyParts,1)) intValue];
    if (!modulus || exponent<3) return nil;
    */
}

- (MYPublicKey*) issuerPublicKey {
    if (_issuer)
        return _issuer.publicKey;
    else if (self.isSelfSigned)
        return self.subjectPublicKey;
    else
        return nil;
}


- (NSData*) signedData {
    // The root object is a sequence; we want to extract the 1st object of that sequence.
    const UInt8 *certStart = _data.bytes;
    const UInt8 *start = MYBERGetContents(_data, nil);
    if (!start) return nil;
    size_t length = MYBERGetLength([NSData dataWithBytesNoCopy: (void*)start
                                                        length: _data.length - (start-certStart)
                                                  freeWhenDone: NO],
                                   NULL);
    if (length==0)
        return nil;
    return [NSData dataWithBytes: start length: (start + length - certStart)];
}

- (MYOID*) signatureAlgorithmID {
    return $castIf(MYOID, $atIf($castIf(NSArray,$atIf(_root,1)), 0));
}

- (NSData*) signature {
    id signature = $atIf(_root,2);
    if ([signature isKindOfClass: [MYBitString class]])
        signature = [signature bits];
    return $castIf(NSData,signature);
}

- (BOOL) validateSignature {
    if (!$equal(self.signatureAlgorithmID, [MYParsedCertificate RSAWithSHA1AlgorithmID]))
        return NO;
    NSData *signedData = self.signedData;
    NSData *signature = self.signature;
    MYPublicKey *pubKey = self.issuerPublicKey;
    if (!signature || !pubKey) return NO;
    return [pubKey verifySignature: signature ofData: signedData];
}


@end




TestCase(ParsedCert) {
    auto void testCert(NSString *filename, BOOL selfSigned);
    testCert(@"../../Tests/selfsigned.cer", YES);
    testCert(@"../../Tests/iphonedev.cer", NO);
    auto void testCert(NSString *filename, BOOL selfSigned) {
        Log(@"--- Creating MYParsedCertificate from %@", filename);
        NSData *certData = [NSData dataWithContentsOfFile: filename];
        //Log(@"Cert Data =\n%@", certData);
        NSError *error = nil;
        MYParsedCertificate *pcert = [[MYParsedCertificate alloc] initWithCertificateData: certData 
                                                                                    error: &error];
        CAssertNil(error);
        CAssert(pcert != nil);
        
        CAssertEq(pcert.isSelfSigned, selfSigned);
        
        NSData *signedData = pcert.signedData;
        //Log(@"Signed Data = (length=%x)\n%@", signedData.length, signedData);
        CAssertEqual(signedData, [certData subdataWithRange: NSMakeRange(4,signedData.length)]);
        
        Log(@"AlgID = %@", pcert.signatureAlgorithmID);
        Log(@"Signature = %@", pcert.signature);
        CAssertEqual(pcert.signatureAlgorithmID, [MYParsedCertificate RSAWithSHA1AlgorithmID]);
        CAssert(pcert.signature != nil);
        Log(@"Subject Public Key = %@", pcert.subjectPublicKey);
        CAssert(pcert.subjectPublicKey);
        if (selfSigned) {
            Log(@"Issuer Public Key = %@", pcert.issuerPublicKey);
            CAssert(pcert.issuerPublicKey);
            
            CAssert(pcert.validateSignature);
        }
    }
}    



/* Parsed form of selfsigned.cer:
 
Sequence:                           <-- top
    Sequence:                       <-- info
        MYASN1Object[2/0]:          <-- version (int, constructed)
            2
        1                           <-- serial number
        Sequence:
            {1 2 840 113549 1 1 1}  <-- algorithm ID
        Sequence:                   <-- issuer
            Set:
                Sequence:
                    {2 5 4 4}
                    Widdershins
            Set:
                Sequence:
                    {1 2 840 113549 1 9 1}
                    waldo@example.com
            Set:
                Sequence:
                    {2 5 4 3}
                    waldo
            Set:
                Sequence:
                    {2 5 4 42}
                    Waldo
            Set:
                Sequence:
                    {2 5 4 13}
                    Just a fictitious person
        Sequence:                       <--validity
            2009-04-12 21:54:35 -0700
            2010-04-13 21:54:35 -0700
        Sequence:                       <-- subject
            Set:
                Sequence:
                    {2 5 4 4}
                    Widdershins
            Set:
                Sequence:
                    {1 2 840 113549 1 9 1}
                    waldo@example.com
            Set:
                Sequence:
                    {2 5 4 3}
                    waldo
            Set:
                Sequence:
                    {2 5 4 42}
                    Waldo
            Set:
                Sequence:
                    {2 5 4 13}
                    Just a fictitious person
        Sequence:                               <-- public key info
            Sequence:
                {1 2 840 113549 1 1 1}          <-- algorithm ID (RSA)
                <null>
            MYBitString<3082010a 02820101 0095713c 360badf2 d8575ebd 278fa26b a2e6d05e 1eb04eaa 9fa6f11b fd341556 038b3077 525c7adb f5aedf3b 249b08e6 7f77af26 7ff2feb8 5f4ccb96 5269dbd2 f01f19b6 55fc4ea3 a85f2ede 11ff80f8 fc23e662 f263f685 06a9ec07 f7ee4249 af184f21 2d9253d8 7f6f7cbc 96e6ba5c abc8f4e7 3bf6100b 06dcf3ee 999d4170 f5dd005d a24a54a1 3edaddd5 0675409d 6728a387 5fa71898 ebf7d93d 4af8742d f9a0e9ad 6dc21cfa fc2d1967 e692575b 56e5376c 8cf008e8 a442d787 6843a92e 9501b144 8a75adef 5e804fec 6d09740d 1ea8442e 67fac3be c5ea3af5 d95d9f95 2c507711 01c45942 28ad1410 23525324 62848476 d987d3c7 d65f9057 daf1e853 77020301 0001>        <-- DER-encoded key
        MYASN1Object[2/3]:
            Sequence:
                Sequence:
                    {2 5 29 15}
                    <030202fc>
                Sequence:
                    {2 5 29 37}
                    <301a0608 2b060105 05070301 06082b06 01050507 03020604 551d2500>
    Sequence:
        {1 2 840 113549 1 1 5}
        <null>
    MYBitString<79c8e789 50a11fcb 7398f5fe 0cfa2595 b2476f53 62dfbea2 70ae3a8b fdaf5a57 39be6101 fc5e0929 e57a0b2b 41e3ab52 f78ef1b5 ecc8848c da7f42aa b57c3df4 df4125a9 db4e6388 197c2a1c e326c1a5 5203b4ef da057b91 4abc43aa 3eeee6aa fe4303c3 0f000175 16b916b5 72f8b74f c682a06f 920e3bbf a16cdad8 fce3f184 adccc61e 8d3b44e5 8bd103f0 46310f6a 992f240a b290354c 04c519c9 22276df6 310ccb8e 942e38f6 555ca40b 71482e52 146a9988 f021c2c0 2d285db5 59d48eaf 7b20559f 068ea1a0 f07fbaee 29284ada 28bf8344 f435f30f 6263f0c9 9c4920ce a1b7c6c0 9cfa3bbb af5a0fee 5b0e94eb 9c57d28b 1bb9c977 be53e4bb b675ffaa>
*/