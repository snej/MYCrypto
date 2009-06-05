//
//  MYParsedCertificate.m
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

// References:
// <http://www.columbia.edu/~ariel/ssleay/layman.html>
// <http://en.wikipedia.org/wiki/X.509>
// <http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt>


#import "MYParsedCertificate.h"
#import "MYASN1Object.h"
#import "MYOID.h"
#import "MYBERParser.h"
#import "MYDEREncoder.h"
#import "MYPublicKey.h"
#import "MYPrivateKey.h"
#import "MYCertificate.h"
#import "MYErrorUtils.h"


#define kDefaultExpirationTime (60.0 * 60.0 * 24.0 * 365.0)


static id $atIf(NSArray *array, NSUInteger index) {
    return index < array.count ?[array objectAtIndex: index] :nil;
}


@implementation MYParsedCertificate


static MYOID *kRSAAlgorithmID, *kRSAWithSHA1AlgorithmID, *kCommonNameOID,
            *kGivenNameOID, *kSurnameOID, *kDescriptionOID, *kEmailOID;


+ (void) initialize {
    if (!kEmailOID) {
        kRSAAlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 1,}
                                                      count: 7];
        kRSAWithSHA1AlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 5}
                                                              count: 7];
        kCommonNameOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 3}
                                                     count: 4];
        kGivenNameOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 42}
                                                    count: 4];
        kSurnameOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 4}
                                                  count: 4];
        kDescriptionOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 13}
                                                count: 7];
        kEmailOID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 9, 1}
                                                count: 7];
    }
    
}

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
    [_data release];
    [super dealloc];
}


- (NSArray*) _info       {return $castIf(NSArray,$atIf(_root,0));}

- (NSArray*) _validDates {return $castIf(NSArray, [self._info objectAtIndex: 4]);}

- (NSArray*) _pairForOID: (MYOID*)oid atInfoIndex: (unsigned)infoIndex {
    NSArray *names = $castIf(NSArray, $atIf(self._info, infoIndex));
    for (id nameEntry in names) {
        for (id pair in $castIf(NSSet,nameEntry)) {
            if ([pair isKindOfClass: [NSArray class]] && [pair count] == 2) {
                if ($equal(oid, [pair objectAtIndex: 0]))
                    return pair;
            }
        }
    }
    return nil;
}

- (NSString*) _stringForOID: (MYOID*)oid atInfoIndex: (unsigned)infoIndex {
    return [[self _pairForOID: oid atInfoIndex: infoIndex] objectAtIndex: 1];
}


@synthesize issuer=_issuer, certificateData=_data;


- (NSDate*) validFrom       {return $castIf(NSDate, $atIf(self._validDates, 0));}
- (NSDate*) validTo         {return $castIf(NSDate, $atIf(self._validDates, 1));}
- (NSString*) commonName    {return [self _stringForOID: kCommonNameOID atInfoIndex: 5];}
- (NSString*) givenName     {return [self _stringForOID: kGivenNameOID atInfoIndex: 5];}
- (NSString*) surname       {return [self _stringForOID: kSurnameOID atInfoIndex: 5];}
- (NSString*) description   {return [self _stringForOID: kDescriptionOID atInfoIndex: 5];}
- (NSString*) emailAddress  {return [self _stringForOID: kEmailOID atInfoIndex: 5];}

- (BOOL) isSigned           {return [_root count] >= 3;}

- (BOOL) isRoot {
    id issuer = $atIf(self._info,3);
    return $equal(issuer, $atIf(self._info,5)) || $equal(issuer, $array());
}


- (MYPublicKey*) subjectPublicKey {
    NSArray *keyInfo = $cast(NSArray, $atIf(self._info, 6));
    MYOID *keyAlgorithmID = $castIf(MYOID, $atIf($castIf(NSArray,$atIf(keyInfo,0)), 0));
    if (!$equal(keyAlgorithmID, kRSAAlgorithmID))
        return nil;
    MYBitString *keyData = $cast(MYBitString, $atIf(keyInfo, 1));
    if (!keyData) return nil;
    return [[[MYPublicKey alloc] initWithKeyData: keyData.bits] autorelease];
}

- (MYPublicKey*) issuerPublicKey {
    if (_issuer)
        return _issuer.publicKey;
    else if (self.isRoot)
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
    if (!$equal(self.signatureAlgorithmID, kRSAWithSHA1AlgorithmID))
        return NO;
    NSData *signedData = self.signedData;
    NSData *signature = self.signature;
    MYPublicKey *pubKey = self.issuerPublicKey;
    if (!signature || !pubKey) return NO;
    return [pubKey verifySignature: signature ofData: signedData];
}


#pragma mark -
#pragma mark CERTIFICATE GENERATION:


- (id) initWithPublicKey: (MYPublicKey*)pubKey {
    Assert(pubKey);
    self = [super init];
    if (self != nil) {
        id empty = [NSNull null];
        id version = [[MYASN1Object alloc] initWithTag: 0 ofClass: 2 components: $array($object(0))];
        _root = $array( $marray(version,
                                empty,       // serial #
                                $array(kRSAAlgorithmID),
                                $marray(),
                                $marray(empty, empty),
                                $marray(),
                                $array( $array(kRSAAlgorithmID, empty),
                                       [MYBitString bitStringWithData: pubKey.keyData] ) ) );
        [version release];
        [_root retain];
    }
    return self;
}


- (void) _setString: (NSString*)value forOID: (MYOID*)oid atInfoIndex: (unsigned)infoIndex {
    NSMutableArray *pair = (NSMutableArray*) [self _pairForOID: oid atInfoIndex: infoIndex];
    if (pair) {
        [pair replaceObjectAtIndex: 1 withObject: value];
    } else {
        NSMutableArray *names = $castIf(NSMutableArray, $atIf(self._info, infoIndex));
        [names addObject: [NSSet setWithObject: $marray(oid,value)]];
    }
}


- (void) setValidFrom: (NSDate*)validFrom {
    [(NSMutableArray*)self._validDates replaceObjectAtIndex: 0 withObject: validFrom];
}

- (void) setValidTo: (NSDate*)validTo {
    [(NSMutableArray*)self._validDates replaceObjectAtIndex: 1 withObject: validTo];
}

- (void) setCommonName: (NSString*)commonName {
    [self _setString: commonName forOID: kCommonNameOID atInfoIndex: 5];
}

- (void) setGivenName: (NSString*)givenName {
    [self _setString: givenName forOID: kGivenNameOID atInfoIndex: 5];
}

- (void) setSurname: (NSString*)surname {
    [self _setString: surname forOID: kSurnameOID atInfoIndex: 5];
}

- (void) setDescription: (NSString*)description {
    [self _setString: description forOID: kDescriptionOID atInfoIndex: 5];
}

- (void) setEmailAddress: (NSString*)emailAddress {
    [self _setString: emailAddress forOID: kEmailOID atInfoIndex: 5];
}


- (BOOL) selfSignWithPrivateKey: (MYPrivateKey*)privateKey error: (NSError**)outError {
    // Copy subject to issuer:
    NSMutableArray *info = (NSMutableArray*)self._info;
    [info replaceObjectAtIndex: 3 withObject: [info objectAtIndex: 5]];
    
    // Set serial number if there isn't one yet:
    if (!$castIf(NSNumber, [info objectAtIndex: 1])) {
        UInt64 serial = floor(CFAbsoluteTimeGetCurrent() * 1000);
        [info replaceObjectAtIndex: 1 withObject: $object(serial)];
    }
    
    // Set up valid date range if there isn't one yet:
    NSDate *validFrom = self.validFrom;
    if (!validFrom)
        validFrom = self.validFrom = [NSDate date];
    NSDate *validTo = self.validTo;
    if (!validTo)
        self.validTo = [validFrom addTimeInterval: kDefaultExpirationTime]; 
    
    // Append signature to cert structure:
    NSData *dataToSign = [MYDEREncoder encodeRootObject: info error: outError];
    if (!dataToSign)
        return NO;
    setObj(&_root, $array(info, 
                          $array(kRSAWithSHA1AlgorithmID, [NSNull null]),
                          [MYBitString bitStringWithData: [privateKey signData: dataToSign]]));
    
    setObj(&_data, [MYDEREncoder encodeRootObject: _root error: outError]);
    return _data!=nil;
}


@end




#if DEBUG


static MYParsedCertificate* testCert(NSString *filename, BOOL selfSigned) {
    Log(@"--- Creating MYParsedCertificate from %@", filename);
    NSData *certData = [NSData dataWithContentsOfFile: filename];
    //Log(@"Cert Data =\n%@", certData);
    NSError *error = nil;
    MYParsedCertificate *pcert = [[MYParsedCertificate alloc] initWithCertificateData: certData 
                                                                                error: &error];
    CAssertNil(error);
    CAssert(pcert != nil);
    
    CAssertEq(pcert.isRoot, selfSigned);
    
    NSData *signedData = pcert.signedData;
    //Log(@"Signed Data = (length=%x)\n%@", signedData.length, signedData);
    CAssertEqual(signedData, [certData subdataWithRange: NSMakeRange(4,signedData.length)]);
    
    Log(@"AlgID = %@", pcert.signatureAlgorithmID);
    Log(@"Signature = %@", pcert.signature);
    CAssertEqual(pcert.signatureAlgorithmID, kRSAWithSHA1AlgorithmID);
    CAssert(pcert.signature != nil);
    Log(@"Subject Public Key = %@", pcert.subjectPublicKey);
    CAssert(pcert.subjectPublicKey);
    if (selfSigned) {
        Log(@"Issuer Public Key = %@", pcert.issuerPublicKey);
        CAssert(pcert.issuerPublicKey);
        
        CAssert(pcert.validateSignature);
    }
    Log(@"Common Name = %@", pcert.commonName);
    Log(@"Given Name  = %@", pcert.givenName);
    Log(@"Surname     = %@", pcert.surname);
    Log(@"Desc        = %@", pcert.description);
    Log(@"Email       = %@", pcert.emailAddress);
    return pcert;
}


TestCase(ParsedCert) {
    testCert(@"../../Tests/selfsigned.cer", YES);
    testCert(@"../../Tests/iphonedev.cer", NO);
}


#import "MYKeychain.h"

TestCase(CreateCert) {
    MYPrivateKey *privateKey = [[MYKeychain defaultKeychain] generateRSAKeyPairOfSize: 512];
    MYParsedCertificate *pcert = [[MYParsedCertificate alloc] initWithPublicKey: privateKey.publicKey];
    pcert.commonName = @"testcase";
    pcert.givenName = @"Test";
    pcert.surname = @"Case";
    pcert.description = @"Just a test certificate created by MYCrypto";
    pcert.emailAddress = @"testcase@example.com";

    CAssertEqual(pcert.commonName, @"testcase");
    CAssertEqual(pcert.givenName, @"Test");
    CAssertEqual(pcert.surname, @"Case");
    CAssertEqual(pcert.description, @"Just a test certificate created by MYCrypto");
    CAssertEqual(pcert.emailAddress, @"testcase@example.com");
    
    Log(@"Signing...");
    NSError *error;
    CAssert([pcert selfSignWithPrivateKey: privateKey error: &error]);
    CAssertNil(error);
    NSData *certData = pcert.certificateData;
    Log(@"Generated cert = \n%@", certData);
    CAssert(certData);
    [certData writeToFile: @"../../Tests/generated.cer" atomically: YES];
    MYParsedCertificate *pcert2 = testCert(@"../../Tests/generated.cer", YES);
    
    Log(@"Verifying...");
    CAssertEqual(pcert2.commonName, @"testcase");
    CAssertEqual(pcert2.givenName, @"Test");
    CAssertEqual(pcert2.surname, @"Case");
    CAssertEqual(pcert2.description, @"Just a test certificate created by MYCrypto");
    CAssertEqual(pcert2.emailAddress, @"testcase@example.com");
}

#endif




/* Parsed form of selfsigned.cer:
 
Sequence:                           <-- top
    Sequence:                       <-- info
        MYASN1Object[2/0]:          <-- version (tag=0, constructed)
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
                Sequence:                   <-- surname
                    {2 5 4 4}
                    Widdershins
            Set:
                Sequence:                   <-- email
                    {1 2 840 113549 1 9 1}
                    waldo@example.com
            Set:
                Sequence:                   <-- common name
                    {2 5 4 3}
                    waldo
            Set:
                Sequence:                   <-- first name
                    {2 5 4 42}
                    Waldo
            Set:
                Sequence:                   <-- description
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