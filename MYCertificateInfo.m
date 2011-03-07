//
//  MYCertificateInfo.m
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

// References:
// <http://tools.ietf.org/html/rfc3280> "RFC 3280: Internet X.509 Certificate Profile"
// <http://www.columbia.edu/~ariel/ssleay/layman.html> "Layman's Guide To ASN.1/BER/DER"
// <http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt> "X.509 Style Guide"
// <http://en.wikipedia.org/wiki/X.509> Wikipedia article on X.509


#import "MYCertificateInfo.h"
#import "MYCrypto.h"
#import "MYASN1Object.h"
#import "MYOID.h"
#import "MYBERParser.h"
#import "MYDEREncoder.h"
#import "MYErrorUtils.h"


#define kDefaultExpirationTime (60.0 * 60.0 * 24.0 * 365.0)     /* that's 1 year */

/*  X.509 version number to generate. Even though my code doesn't (yet) add any of the post-v1
    metadata, it's necessary to write v3 or the resulting certs won't be accepted on some platforms,
    notably iPhone OS.
    "This field is used mainly for marketing purposes to claim that software is X.509v3 compliant 
    (even when it isn't)." --Peter Gutmann */
#define kCertRequestVersionNumber 3


/* "Safe" NSArray accessor -- returns nil if out of range. */
static id $atIf(NSArray *array, NSUInteger index) {
    return index < array.count ?[array objectAtIndex: index] :nil;
}


@interface MYCertificateName ()
- (id) _initWithComponents: (NSArray*)components;
@end

@interface MYCertificateExtensions ()
- (id) _initWithComponents: (NSArray*)components;
@end

@interface MYCertificateInfo ()
@property (retain) NSArray *_root;
@end


#pragma mark -
@implementation MYCertificateInfo


static MYOID *kRSAAlgorithmID, *kRSAWithSHA1AlgorithmID, *kRSAWithSHA256AlgorithmID,
             *kRSAWithMD5AlgorithmID, *kRSAWithMD2AlgorithmID,
             *kCommonNameOID, *kGivenNameOID, *kSurnameOID, *kDescriptionOID, *kEmailOID;
MYOID *kKeyUsageOID, *kExtendedKeyUsageOID,
      *kExtendedKeyUsageServerAuthOID, *kExtendedKeyUsageClientAuthOID,
      *kExtendedKeyUsageCodeSigningOID, *kExtendedKeyUsageEmailProtectionOID;


+ (void) initialize {
    if (!kEmailOID) {
        kRSAAlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 1,}
                                                      count: 7];
        kRSAWithSHA1AlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 5}
                                                              count: 7];
        kRSAWithSHA256AlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 11}
                                                                count:7];
        kRSAWithMD5AlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 4 }
                                                             count:7];
        kRSAWithMD2AlgorithmID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 1, 2}
                                                             count:7];
        kCommonNameOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 3}
                                                     count: 4];
        kGivenNameOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 42}
                                                    count: 4];
        kSurnameOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 4}
                                                  count: 4];
        kDescriptionOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 4, 13}
                                                count: 4];
        kEmailOID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 2, 840, 113549, 1, 9, 1}
                                                count: 7];
        kKeyUsageOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 29, 15}
                                                           count: 4];
        kExtendedKeyUsageOID = [[MYOID alloc] initWithComponents: (UInt32[]){2, 5, 29, 37}
                                                           count: 4];

        kExtendedKeyUsageServerAuthOID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 3, 6, 1, 5, 5, 7, 3, 1}
                                                           count: 9];
        kExtendedKeyUsageClientAuthOID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 3, 6, 1, 5, 5, 7, 3, 2}
                                                                     count: 9];
        kExtendedKeyUsageCodeSigningOID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 3, 6, 1, 5, 5, 7, 3, 3}
                                                                     count: 9];
        kExtendedKeyUsageEmailProtectionOID = [[MYOID alloc] initWithComponents: (UInt32[]){1, 3, 6, 1, 5, 5, 7, 3, 4}
                                                                     count: 9];

    }
}


- (id) initWithRoot: (NSArray*)root
{
    self = [super init];
    if (self != nil) {
        _root = [root retain];
    }
    return self;
}

+ (NSString*) validate: (id)root {
    NSArray *top = $castIf(NSArray,root);
    if (top.count < 3)
        return @"Too few top-level components";
    NSArray *info = $castIf(NSArray, [top objectAtIndex: 0]);
    if (info.count < 6) {
        return @"Too few identity components";      // there should be 7, but version has a default
    } else if (info.count > 6) {
        MYASN1Object *version = $castIf(MYASN1Object, [info objectAtIndex: 0]);
        if (!version || version.tag != 0)
            return @"Missing or invalid version";
        NSArray *versionComps = $castIf(NSArray, version.components);
        if (!versionComps || versionComps.count != 1)
            return @"Invalid version";
        NSNumber *versionNum = $castIf(NSNumber, [versionComps objectAtIndex: 0]);
        if (!versionNum || versionNum.intValue < 0 || versionNum.intValue > 2)
            return @"Unrecognized version number";
    }
    return nil;
}


- (id) initWithCertificateData: (NSData*)data error: (NSError**)outError;
{
    if (outError) *outError = nil;
    id root = MYBERParse(data,outError);
    NSString *errorMsg = [[self class] validate: root];
    if (errorMsg) {
        if (outError && !*outError)
            *outError = MYError(2, MYASN1ErrorDomain, @"Invalid certificate: %@", errorMsg);
        [self release];
        return nil;
    }

    self = [self initWithRoot: root];
    if (self) {
        _data = [data copy];
    }
    return self;
}

- (void) dealloc
{
    [_root release];
    [_data release];
    [super dealloc];
}

- (BOOL) isEqual: (id)object {
    return [object isKindOfClass: [MYCertificateInfo class]]
        && [_root isEqual: ((MYCertificateInfo*)object)->_root];
}

/* _info returns an NSArray representing the thing called TBSCertificate in the spec:
    TBSCertificate ::= SEQUENCE {
        version          [ 0 ]  Version DEFAULT v1(0),
        serialNumber            CertificateSerialNumber,
        signature               AlgorithmIdentifier,
        issuer                  Name,
        validity                Validity,
        subject                 Name,
        subjectPublicKeyInfo    SubjectPublicKeyInfo,
        issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
        extensions        [ 3 ] Extensions OPTIONAL
        }
*/
- (NSArray*) _info {
    NSArray* info = $castIf(NSArray,$atIf(_root,0));
    if (info.count >= 7)
        return info;
    // If version field is missing, insert it explicitly so the array indices will be normal:
    NSMutableArray* minfo = [[info mutableCopy] autorelease];
    [minfo insertObject: $object(0) atIndex: 0];
    return minfo;
}

- (NSArray*) _validDates {return $castIf(NSArray, [self._info objectAtIndex: 4]);}

@synthesize _root;


- (NSDate*) validFrom       {return $castIf(NSDate, $atIf(self._validDates, 0));}
- (NSDate*) validTo         {return $castIf(NSDate, $atIf(self._validDates, 1));}

- (MYCertificateName*) subject {
    return [[[MYCertificateName alloc] _initWithComponents: [self._info objectAtIndex: 5]] autorelease];
}

- (MYCertificateName*) issuer {
    return [[[MYCertificateName alloc] _initWithComponents: [self._info objectAtIndex: 3]] autorelease];
}

- (MYCertificateExtensions*)extensions {
    NSArray* info = self._info;
    for (NSUInteger i=7; i<info.count; i++) {
        MYASN1Object* obj = $castIf(MYASN1Object, [info objectAtIndex:i]);
        if (obj.tag == 3) {
            NSArray* extensions = $castIf(NSArray, $atIf(obj.components, 0));
            if (!extensions)
                return nil;
            return [[[MYCertificateExtensions alloc] _initWithComponents: extensions] autorelease];
        }
    }
    return nil;
}

- (BOOL) isSigned           {return [_root count] >= 3;}

- (BOOL) isRoot {
    id issuer = $atIf(self._info,3);
    return $equal(issuer, $atIf(self._info,5)) || $equal(issuer, $array());
}


- (NSData*) subjectPublicKeyData {
    NSArray *keyInfo = $cast(NSArray, $atIf(self._info, 6));
    MYOID *keyAlgorithmID = $castIf(MYOID, $atIf($castIf(NSArray,$atIf(keyInfo,0)), 0));
    if (!$equal(keyAlgorithmID, kRSAAlgorithmID))
        return nil;
    return $cast(MYBitString, $atIf(keyInfo, 1)).bits;
}

- (MYPublicKey*) subjectPublicKey {
    NSData *keyData = self.subjectPublicKeyData;
    if (!keyData) return nil;
    return [[[MYPublicKey alloc] initWithKeyData: keyData] autorelease];
}

- (NSData*) signedData {
    if (!_data)
        return nil;
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

- (BOOL) verifySignatureWithKey: (MYPublicKey*)issuerPublicKey {
    // Determine which signature algorithm to use:
    CSSM_ALGORITHMS algorithm;
    MYOID* algID = self.signatureAlgorithmID;
    if ($equal(algID, kRSAWithSHA1AlgorithmID))
        algorithm = CSSM_ALGID_SHA1WithRSA;
    else if ($equal(algID, kRSAWithSHA256AlgorithmID))
        algorithm = CSSM_ALGID_SHA256WithRSA;
    else if ($equal(algID, kRSAWithMD5AlgorithmID))
        algorithm = CSSM_ALGID_MD5WithRSA;
    else if ($equal(algID, kRSAWithMD2AlgorithmID))
        algorithm = CSSM_ALGID_MD2WithRSA;
    else {
        Warn(@"MYCertificateInfo can't verify: unknown signature algorithm %@", algID);
        return NO;
    }
    
    NSData *signedData = self.signedData;
    NSData *signature = self.signature;
    return signedData && signature && [issuerPublicKey verifySignature: self.signature
                                                                ofData: self.signedData
                                                         withAlgorithm: algorithm];
}


@end




#pragma mark -
@implementation MYCertificateRequest

- (id) initWithPublicKey: (MYPublicKey*)publicKey {
    Assert(publicKey);
    id empty = [NSNull null];
    id version = [[MYASN1Object alloc] initWithTag: 0 
                                           ofClass: 2
                                        components: $array($object(kCertRequestVersionNumber - 1))];
    id extensions = [[MYASN1Object alloc] initWithTag:3
                                              ofClass:2
                                           components: $array($marray())];
    NSArray *root = $array( $marray(version,
                                    empty,       // serial #
                                    $array(kRSAAlgorithmID),
                                    $marray(),
                                    $marray(empty, empty),
                                    $marray(),
                                    $array( $array(kRSAAlgorithmID, empty),
                                           [MYBitString bitStringWithData: publicKey.keyData] ),
                                    extensions) );
    self = [super initWithRoot: root];
    [version release];
    [extensions release];
    if (self) {
        _publicKey = publicKey.retain;
    }
    return self;
}
    
- (void) dealloc
{
    [_publicKey release];
    [super dealloc];
}


- (NSDate*) validFrom       {return [super validFrom];}
- (NSDate*) validTo         {return [super validTo];}

- (void) setValidFrom: (NSDate*)validFrom {
    [(NSMutableArray*)self._validDates replaceObjectAtIndex: 0 withObject: validFrom];
}

- (void) setValidTo: (NSDate*)validTo {
    [(NSMutableArray*)self._validDates replaceObjectAtIndex: 1 withObject: validTo];
}


- (void) fillInValues {
    NSMutableArray *info = (NSMutableArray*)self._info;
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
    if (!validTo) {
#if MAC_OS_X_VERSION_MIN_REQUIRED <= MAC_OS_X_VERSION_10_5
        self.validTo = [validFrom addTimeInterval: kDefaultExpirationTime];
#else
        self.validTo = [validFrom dateByAddingTimeInterval: kDefaultExpirationTime];
#endif
    }
}


- (NSData*) requestData: (NSError**)outError {
    [self fillInValues];
    return [MYDEREncoder encodeRootObject: self._info error: outError];
}


- (NSData*) selfSignWithPrivateKey: (MYPrivateKey*)privateKey 
                             error: (NSError**)outError 
{
    AssertEqual(privateKey.publicKey, _publicKey);  // Keys must form a pair
    
    // Copy subject to issuer:
    NSMutableArray *info = (NSMutableArray*)self._info;
    [info replaceObjectAtIndex: 3 withObject: [info objectAtIndex: 5]];
    
    // Sign the request:
    NSData *dataToSign = [self requestData: outError];
    if (!dataToSign)
        return nil;
    MYBitString *signature = [MYBitString bitStringWithData: [privateKey signData: dataToSign]];
    
    // Generate and encode the certificate:
    NSArray *root = $array(info, 
                           $array(kRSAWithSHA1AlgorithmID, [NSNull null]),
                           signature);
    return [MYDEREncoder encodeRootObject: root error: outError];
}


- (MYIdentity*) createSelfSignedIdentityWithPrivateKey: (MYPrivateKey*)privateKey
                                                 error: (NSError**)outError
{
    Assert(privateKey.keychain!=nil);
    NSData *certData = [self selfSignWithPrivateKey: privateKey error: outError];
    if (!certData)
        return nil;
    MYCertificate *cert = [privateKey.keychain importCertificate: certData];
    Assert(cert!=nil);
    Assert(cert.keychain!=nil);
    AssertEqual(cert.publicKey.keyData, _publicKey.keyData);
    MYIdentity *identity = cert.identity;
    Assert(identity!=nil);
    return identity;
}


@end



#pragma mark -
@implementation MYCertificateName

- (id) _initWithComponents: (NSArray*)components
{
    self = [super init];
    if (self != nil) {
        _components = [components retain];
    }
    return self;
}

- (void) dealloc
{
    [_components release];
    [super dealloc];
}

- (BOOL) isEqual: (id)object {
    return [object isKindOfClass: [MYCertificateName class]]
        && [_components isEqual: ((MYCertificateName*)object)->_components];
}

- (NSArray*) _pairForOID: (MYOID*)oid {
    for (id nameEntry in _components) {
        for (id pair in $castIf(NSSet,nameEntry)) {
            if ([pair isKindOfClass: [NSArray class]] && [pair count] == 2) {
                if ($equal(oid, [pair objectAtIndex: 0]))
                    return pair;
            }
        }
    }
    return nil;
}

- (NSString*) stringForOID: (MYOID*)oid {
    return [[self _pairForOID: oid] objectAtIndex: 1];
}

- (void) setString: (NSString*)value forOID: (MYOID*)oid {
    NSMutableArray *pair = (NSMutableArray*) [self _pairForOID: oid];
    if (pair) {
        if (value)
            [pair replaceObjectAtIndex: 1 withObject: value];
        else
            Assert(NO,@"-setString:forOID: removing strings is unimplemented");//FIX
    } else {
        if (value)
            [(NSMutableArray*)_components addObject: [NSSet setWithObject: $marray(oid,value)]];
    }
}

- (NSString*) commonName    {return [self stringForOID: kCommonNameOID];}
- (NSString*) givenName     {return [self stringForOID: kGivenNameOID];}
- (NSString*) surname       {return [self stringForOID: kSurnameOID];}
- (NSString*) nameDescription {return [self stringForOID: kDescriptionOID];}
- (NSString*) emailAddress  {return [self stringForOID: kEmailOID];}

- (void) setCommonName: (NSString*)commonName   {[self setString: commonName forOID: kCommonNameOID];}
- (void) setGivenName: (NSString*)givenName     {[self setString: givenName forOID: kGivenNameOID];}
- (void) setSurname: (NSString*)surname         {[self setString: surname forOID: kSurnameOID];}
- (void) setNameDescription: (NSString*)desc    {[self setString: desc forOID: kDescriptionOID];}
- (void) setEmailAddress: (NSString*)email      {[self setString: email forOID: kEmailOID];}


@end






#pragma mark -
@implementation MYCertificateExtensions

- (id) _initWithComponents: (NSArray*)extensions
{
    self = [super init];
    if (self != nil) {
        _extensions = [extensions retain];
    }
    return self;
}

- (void) dealloc
{
    [_extensions release];
    [super dealloc];
}

- (NSArray*) _itemForOID: (MYOID*)oid {
    for (id item in _extensions) {
        NSArray* extension = $castIf(NSArray, item);
        if (extension.count == 3 && [[extension objectAtIndex:0] isEqual: oid])
            return extension;
    }
    return nil;
}

- (NSArray*) extensionOIDs {
    NSMutableArray* oids = $marray();
    for (id item in _extensions) {
        NSArray* extension = $castIf(NSArray, item);
        if (extension.count == 3) {
            MYOID* oid = $castIf(MYOID, [extension objectAtIndex:0]);
            if (oid)
                [oids addObject:oid];
        }
    }
    return oids;
}


- (id) extensionForOID: (MYOID*)oid isCritical: (BOOL*)outIsCritical {
    NSArray* extension = [self _itemForOID:oid];
    if (!extension)
        return nil;
    if (outIsCritical)
        *outIsCritical = [$castIf(NSNumber, [extension objectAtIndex: 1]) boolValue];
    NSData* ber = $castIf(NSData, [extension objectAtIndex: 2]);
    if (!ber)
        return nil;
    return MYBERParse(ber, NULL);
}

- (void) setExtension: (id)value isCritical: (BOOL)isCritical forOID: (MYOID*)oid {
    NSArray* item = nil;
    if (value) {
        NSData* ber = [MYDEREncoder encodeRootObject: value error: NULL];
        Assert(ber != nil);
        item = $marray(oid, (isCritical ?$true :$false), ber);
    }
    
    NSMutableArray* extension = (NSMutableArray*) [self _itemForOID:oid];
    if (extension) {
        if (item)
            [extension replaceObjectsInRange:NSMakeRange(0,2) withObjectsFromArray:item];
        else
            [(NSMutableArray*)_extensions removeObject: extension];
    } else {
        if (item)
            [(NSMutableArray*)_extensions addObject: item];
    }
}


- (UInt16) keyUsage {
    // RFC 3280 sec. 4.2.1.3
    MYBitString* bits = $castIf(MYBitString, [self extensionForOID:kKeyUsageOID isCritical:NULL]);
    if (!bits)
        return 0;
    const UInt8* bytes = [bits.bits bytes];
    UInt16 value = bytes[0];
    if (bits.bitCount > 8)      // 9 bits are defined, so the value could be multi-byte
        value |= bytes[1] << 8;
    return value;
}

- (void) setKeyUsage: (UInt16)keyUsage {
    MYBitString* bitString = nil;
    if (keyUsage != 0) {
        UInt8 bytes[2] = {keyUsage & 0xFF, keyUsage >> 8};
        size_t length = 1 + (bytes[1] != 0);
        NSData* data = [NSData dataWithBytes: bytes length: length];
        bitString = [[MYBitString alloc] initWithBits: data count: 8*length];
    }
    [self setExtension: bitString 
            isCritical: YES 
                forOID: kKeyUsageOID];
    [bitString release];
}


- (NSSet*) extendedKeyUsage {
    // RFC 3280 sec. 4.2.1.13
    NSArray* oids = $castIf(NSArray, [self extensionForOID: kExtendedKeyUsageOID isCritical: NULL]);
    if (!oids)
        return nil;
    return [NSSet setWithArray:oids];
}

- (void) setExtendedKeyUsage: (NSSet*)usage {
    [self setExtension: (usage.count ?[usage allObjects] :nil)
            isCritical: YES
                forOID: kExtendedKeyUsageOID];
}

@end


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
