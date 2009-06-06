//
//  MYCertGen.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/3/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

//  NOTE: This module has been replaced by MYCertificateInfo, which isn't dependent on
//  CSSM APIs that aren't available on iPhone.

//  Derived from ...

//
//  CertificateGeneration.m
//  Keychain
//
//  Created by Wade Tregaskis on Tue May 27 2003.
//
//  Copyright (c) 2003 - 2007, Wade Tregaskis.  All rights reserved.
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//    * Neither the name of Wade Tregaskis nor the names of any other contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#import "MYCertGen.h"
#import "MYCrypto_Private.h"
#import "MYIdentity.h"
#import <Security/Security.h>



static CSSM_X509_NAME* createNameList( NSDictionary *name );
static CSSM_X509_TIME* timeForNSDate(NSDate *date);

static NSData* NSDataFromDataNoCopy(CSSM_DATA data, BOOL freeWhenDone);

static BOOL intToDER(uint32_t theInt, CSSM_DATA *data);



NSData* MYCertificateCreateTemplate(const CSSM_X509_NAME *subject, const CSSM_X509_NAME *issuer,
                                    NSDate *validFrom, NSDate *validTo,
                                    uint32_t serialNumber,
                                    const CSSM_X509_EXTENSION **extensions, unsigned nExtensions,
                                    MYPublicKey *publicKey,
                                    const CSSM_X509_ALGORITHM_IDENTIFIER *signingAlgorithm,
                                    CSSM_CL_HANDLE clHandle) 
{
    CAssert(subject);
    CAssert(issuer);
    CAssert(publicKey);
    CAssert(signingAlgorithm);
    CAssert(clHandle);

    const CSSM_KEY *cssmPubKey = publicKey.cssmKey;
    if (cssmPubKey->KeyHeader.BlobType != CSSM_KEYBLOB_RAW) {
        cssmPubKey = publicKey._unwrappedCSSMKey;
        if (!cssmPubKey) {
            Warn(@"MYCertificateCreateTemplate: unable to unwrap public key %@", publicKey);
            return nil;
        }
    }

    uint32_t numberOfFields = 5; // always requires at least 5 user-supplied fields
    if (serialNumber)
        ++numberOfFields;
    if (validFrom)
        ++numberOfFields;
    if (validTo)
        ++numberOfFields;
    numberOfFields += nExtensions;
    
    CSSM_FIELD fields[numberOfFields];

    // now we fill in the fields appropriately
    
    uint32_t index = 0;
    fields[index].FieldOid = CSSMOID_X509V1Version;
    intToDER(2, &(fields[index++].FieldValue));

    if (serialNumber) {
        fields[index].FieldOid = CSSMOID_X509V1SerialNumber;
        intToDER(serialNumber, &fields[index].FieldValue);
        index++;
    }

    fields[index].FieldOid = CSSMOID_X509V1IssuerNameCStruct;
    fields[index].FieldValue.Data = (uint8_t*)issuer;
    fields[index++].FieldValue.Length = sizeof(CSSM_X509_NAME);

    fields[index].FieldOid = CSSMOID_X509V1SubjectNameCStruct;
    fields[index].FieldValue.Data = (uint8_t*)subject;
    fields[index++].FieldValue.Length = sizeof(CSSM_X509_NAME);

    if (validFrom) {
        fields[index].FieldOid = CSSMOID_X509V1ValidityNotBefore;
        fields[index].FieldValue.Data = (uint8_t*)timeForNSDate(validFrom);
        fields[index++].FieldValue.Length = sizeof(CSSM_X509_TIME);
    }
    
    if (validTo) {
        fields[index].FieldOid = CSSMOID_X509V1ValidityNotAfter;
        fields[index].FieldValue.Data = (uint8_t*)timeForNSDate(validTo);
        fields[index++].FieldValue.Length = sizeof(CSSM_X509_TIME);
    }
    
    fields[index].FieldOid = CSSMOID_CSSMKeyStruct;
    fields[index].FieldValue.Data = (uint8_t*)cssmPubKey;
    fields[index++].FieldValue.Length = sizeof(CSSM_KEY);

    fields[index].FieldOid = CSSMOID_X509V1SignatureAlgorithmTBS;
    fields[index].FieldValue.Data = (uint8_t*)signingAlgorithm;
    fields[index++].FieldValue.Length = sizeof(CSSM_X509_ALGORITHM_IDENTIFIER);
    
    for (unsigned i=0; i<nExtensions; i++) {
        fields[index].FieldOid = extensions[i]->extnId;
        fields[index].FieldValue.Data = (uint8_t*)extensions[i];
        fields[index++].FieldValue.Length = sizeof(CSSM_X509_EXTENSION);
    }
    CAssert(index == numberOfFields);
    
    CSSM_DATA result = {};
    checkcssm(CSSM_CL_CertCreateTemplate(clHandle, numberOfFields, fields, &result),
              @"CSSM_CL_CertCreateTemplate");
    return NSDataFromDataNoCopy(result, YES);
}


NSData* MYCertificateSign(NSData *certificateTemplate, 
                          MYPrivateKey *privateKey, 
                          CSSM_ALGORITHMS signingAlgorithmID,
                          CSSM_CL_HANDLE cssmCLHandle) 
{

    CAssert(certificateTemplate.length);
    CAssert(privateKey);
        
    NSData *signedCertificate = nil;
    CSSM_CC_HANDLE ccHandle = [privateKey _createSignatureContext: signingAlgorithmID];
    if (ccHandle) {
        CSSM_DATA rawCert = {certificateTemplate.length, (void*)certificateTemplate.bytes};
        CSSM_DATA signedResult = {};
        if (checkcssm(CSSM_CL_CertSign(cssmCLHandle, ccHandle, &rawCert, NULL, 0, &signedResult),
                      @"CSSM_CL_CertSign")) {
            signedCertificate = NSDataFromDataNoCopy(signedResult, YES);
            checkcssm(CSSM_DeleteContext(ccHandle), @"CSSM_DeleteContext");
        }
    }
    return signedCertificate;
}


MYCertificate* MYCertificateCreateSelfSigned(MYPrivateKey *privateKey,
                                             NSDictionary *attributes )
{
    // Extract attributes:
    NSMutableDictionary *subject = [[attributes mutableCopy] autorelease];

    unsigned serialNumber = [[attributes objectForKey: @"Serial Number"] unsignedIntValue];
    [subject removeObjectForKey: @"Serial Number"];

    NSDate *validFrom = [attributes objectForKey: @"Valid From"];
    [subject removeObjectForKey: @"Valid From"];
    NSDate *validTo = [attributes objectForKey: @"Valid To"];
    [subject removeObjectForKey: @"Valid To"];
    
    if (!serialNumber)
        serialNumber = 1;
    if (!validFrom)
        validFrom = [NSCalendarDate date];
    if (!validTo)
        validTo = [validFrom addTimeInterval: 60*60*24*366];
    
    const CSSM_X509_NAME *subjectStruct = createNameList(subject);

    // Create the key-usage extensions for the cert:    
    UInt8 keyUsageBits[2] = {0x00,0xFC};
    // that's binary 111111000; see http://tools.ietf.org/html/rfc3280#section-4.2.1.3
    CSSM_X509_EXTENSION keyUsage = {
        CSSMOID_KeyUsage, 
        false,      // non-critical
        CSSM_X509_DATAFORMAT_PARSED,
        {.parsedValue = &keyUsageBits}
    };
    
    // See http://tools.ietf.org/html/rfc3280#section-4.2.1.13
    struct ExtendedUsageList {
        UInt32 count;
        const CSSM_OID *oids;
    };
    CSSM_OID usageOids[3] = {CSSMOID_ServerAuth, CSSMOID_ClientAuth, CSSMOID_ExtendedKeyUsageAny};
    struct ExtendedUsageList extUsageBits = {3, usageOids};
    CSSM_X509_EXTENSION extendedKeyUsage = {
        CSSMOID_ExtendedKeyUsage,
        false,      // non-critical
        CSSM_X509_DATAFORMAT_PARSED,
        {.parsedValue = &extUsageBits}
    };
    
    const CSSM_X509_EXTENSION* extensions[2] = {&keyUsage, &extendedKeyUsage};
    
    CSSM_X509_ALGORITHM_IDENTIFIER algorithmID = {.algorithm=CSSMOID_RSA};
    CSSM_CL_HANDLE cssmCLHandle = getCLHandle();

    // Now create the certificate request and sign it:
    NSData *template, *signedCertificate = nil;
    
    template = MYCertificateCreateTemplate(subjectStruct, subjectStruct, // issuer==subject (self-signed) 
                                           validFrom, validTo, 
                                           serialNumber, 
                                           extensions, 2,
                                           privateKey.publicKey, 
                                           &algorithmID, 
                                           cssmCLHandle);
    if (!template)
        return nil;
    
    signedCertificate = MYCertificateSign(template, 
                                          privateKey, 
                                          CSSM_ALGID_SHA1WithRSA, 
                                          cssmCLHandle);
    if (!signedCertificate)
        return nil;
    
    return [[[MYCertificate alloc] initWithCertificateData: signedCertificate 
                                                      type: CSSM_CERT_UNKNOWN 
                                                  encoding: CSSM_CERT_ENCODING_UNKNOWN] autorelease];
}



MYIdentity* MYIdentityCreateSelfSigned(MYPrivateKey *privateKey,
                                       NSDictionary *attributes )
{
    MYCertificate *cert = MYCertificateCreateSelfSigned(privateKey, attributes);
    if (!cert)
        return nil;
    if (![privateKey.keychain addCertificate: cert])
        return nil;
    MYIdentity *identity = [[[MYIdentity alloc] initWithCertificateRef: cert.certificateRef] autorelease];
    CAssert(identity);
    return identity;
}



#pragma mark -
#pragma mark HELPER FUNCTIONS:


static void* mallocAutoreleased( size_t size ) {
    NSMutableData *data = [NSMutableData dataWithLength: size];
    return data.mutableBytes;
}

#define callocAutoreleasedArray(TYPE,N)  (TYPE*)mallocAutoreleased( sizeof(TYPE) * (N) )


/*
    CSSM_X509_NAME:
        uint32 numberOfRDNs;
        CSSM_X509_RDN_PTR RelativeDistinguishedName:
            uint32 numberOfPairs;
            CSSM_X509_TYPE_VALUE_PAIR_PTR AttributeTypeAndValue:
                CSSM_OID type;
                CSSM_BER_TAG valueType; // The Tag to be used when this value is BER encoded 
                CSSM_DATA value;
*/


static CSSM_X509_NAME* createNameList( NSDictionary *name ) {
    static NSArray *sNameKeys;
    static CSSM_OID sNameOIDs[7];
    if (!sNameKeys) {
        sNameKeys = [$array(@"Common Name", @"Surname",  @"Description", @"Name", @"Given Name", 
                            @"Email Address", @"Unstructured Name") retain];
        sNameOIDs[0] = CSSMOID_CommonName;
        sNameOIDs[1] = CSSMOID_Surname;
        sNameOIDs[2] = CSSMOID_Description;
        sNameOIDs[3] = CSSMOID_Name;
        sNameOIDs[4] = CSSMOID_GivenName;
        sNameOIDs[5] = CSSMOID_EmailAddress;
        sNameOIDs[6] = CSSMOID_UnstructuredName;
    }
    
    unsigned n = name.count;
    CAssert(n>0);
    CSSM_X509_RDN *rdns = callocAutoreleasedArray(CSSM_X509_RDN, name.count);
    CSSM_X509_RDN *rdn = &rdns[0];
    CSSM_X509_TYPE_VALUE_PAIR *pairs = callocAutoreleasedArray(CSSM_X509_TYPE_VALUE_PAIR, n);
    CSSM_X509_TYPE_VALUE_PAIR *pair = &pairs[0];
    for (NSString *key in name) {
        NSString *value = [name objectForKey: key];
        unsigned index = [sNameKeys indexOfObject: key];
        CAssert(index!=NSNotFound, @"X509 name key '%@' not supported'", key);
        rdn->numberOfPairs = 1;
        rdn->AttributeTypeAndValue = pair;
        pair->type = sNameOIDs[index];
        pair->valueType = BER_TAG_PRINTABLE_STRING;
        pair->value.Data = (void*) value.UTF8String;
        pair->value.Length = strlen((char*)pair->value.Data);
        rdn++;
        pair++;
    }
    CSSM_X509_NAME *outName = callocAutoreleasedArray(CSSM_X509_NAME,1);
    outName->numberOfRDNs = n;
    outName->RelativeDistinguishedName = rdns;
    return outName;
}


#pragma mark -
#pragma mark HELPER FUNCTIONS (from Keychain.framework)


static CSSM_X509_TIME* timeForNSDate(NSDate *date) {
    CAssert(date);
    
    NSCalendarDate *dateGMT = [NSCalendarDate dateWithTimeIntervalSinceReferenceDate: 
                                                            date.timeIntervalSinceReferenceDate];
    [dateGMT setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    
    /* RFC 2549:
     
     4.1.2.5.2  GeneralizedTime
     
     The generalized time type, GeneralizedTime, is a standard ASN.1 type
     for variable precision representation of time.  Optionally, the
     GeneralizedTime field can include a representation of the time
     differential between local and Greenwich Mean Time.
     
     For the purposes of this profile, GeneralizedTime values MUST be
     expressed Greenwich Mean Time (Zulu) and MUST include seconds (i.e.,
     times are YYYYMMDDHHMMSSZ), even where the number of seconds is zero.
     GeneralizedTime values MUST NOT include fractional seconds. */
    
    CSSM_X509_TIME *result = mallocAutoreleased(sizeof(CSSM_X509_TIME));
    result->timeType = BER_TAG_GENERALIZED_TIME;
    result->time.Length = 15;
    result->time.Data = mallocAutoreleased(16);
    [[dateGMT descriptionWithCalendarFormat:@"%Y%m%d%H%M%SZ"] getCString: (char*)(result->time.Data)
                                                               maxLength: 16 
                                                                encoding: NSASCIIStringEncoding];
    return result;
}


static NSData* NSDataFromDataNoCopy(CSSM_DATA data, BOOL freeWhenDone) {
    if (data.Data)
        return [NSData dataWithBytesNoCopy:data.Data length:data.Length freeWhenDone: freeWhenDone];
    else
        return nil;
}


static BOOL intToDER(uint32_t theInt, CSSM_DATA *data) {
    CAssert(data);
    data->Length = 0;
    
    if (theInt < 0x100) {
        data->Data = (uint8_t*)malloc(1);
        
        if (NULL != data->Data) {
            data->Length = 1;

            data->Data[0] = (unsigned char)(theInt);
        }
    } else if (theInt < 0x10000) {
        data->Data = (uint8_t*)malloc(2);
        
        if (NULL != data->Data) {
            data->Length = 2;

            data->Data[0] = (unsigned char)(theInt >> 8);
            data->Data[1] = (unsigned char)(theInt);
        }
    } else if (theInt < 0x1000000) {
        data->Data = (uint8_t*)malloc(3);
        
        if (NULL != data->Data) {
            data->Length = 3;

            data->Data[0] = (unsigned char)(theInt >> 16);
            data->Data[1] = (unsigned char)(theInt >> 8);
            data->Data[2] = (unsigned char)(theInt);
        }
    } else {
        data->Data = (uint8_t*)malloc(4);
        
        if (NULL != data->Data) {
            data->Length = 4;

            data->Data[0] = (unsigned char)(theInt >> 24);
            data->Data[1] = (unsigned char)(theInt >> 16);
            data->Data[2] = (unsigned char)(theInt >> 8);
            data->Data[3] = (unsigned char)(theInt);
        }
    }
    
    return (NULL != data->Data);
}



#pragma mark -
#pragma mark HELPER FUNCTIONS (from Apple's source code):


// From Apple's cuCdsaUtils.cpp, in libsecurity_cdsa_utils:


/*
 * Standard app-level memory functions required by CDSA.
 */
static void * cuAppMalloc (CSSM_SIZE size, void *allocRef)             {return( malloc(size) );}
static void   cuAppFree (void *mem_ptr, void *allocRef)                {free(mem_ptr);}
static void * cuAppRealloc (void *ptr, CSSM_SIZE size, void *allocRef) {return( realloc( ptr, size ) );}
static void * cuAppCalloc (uint32 num, CSSM_SIZE size, void *allocRef) {return( calloc( num, size ) );}

static CSSM_VERSION vers = {2, 0};
static CSSM_API_MEMORY_FUNCS memFuncs = {
    cuAppMalloc,
    cuAppFree,
    cuAppRealloc,
    cuAppCalloc,
    NULL
};

static CSSM_CL_HANDLE cuClStartup()
{
	CSSM_CL_HANDLE clHand;
	
	if (!checkcssm(CSSM_ModuleLoad(&gGuidAppleX509CL,
                                   CSSM_KEY_HIERARCHY_NONE,
                                   NULL,			// eventHandler
                                   NULL), @"CSSM_ModuleLoad"))
        return 0;
    if (!checkcssm(CSSM_ModuleAttach(&gGuidAppleX509CL,
                                     &vers,
                                     &memFuncs,				// memFuncs
                                     0,						// SubserviceID
                                     CSSM_SERVICE_CL,		// SubserviceFlags - Where is this used?
                                     0,						// AttachFlags
                                     CSSM_KEY_HIERARCHY_NONE,
                                     NULL,					// FunctionTable
                                     0,						// NumFuncTable
                                     NULL,					// reserved
                                     &clHand), @"CSSM_ModuleAttach"))
        return 0;
    return clHand;
}
        
CSSM_CL_HANDLE getCLHandle() {
    static CSSM_CL_HANDLE sCLHandle = 0;
    if (!sCLHandle)
        sCLHandle = cuClStartup();
    return sCLHandle;
}


#pragma mark -
#pragma mark TEST CASE:


TestCase(MYCertGen) {
    CSSM_CL_HANDLE cl = getCLHandle();
    Log(@"CSSM_CL_HANDLE = %p", cl);
    CAssert(cl);
    
    Log(@"Generating a key pair...");
    MYPrivateKey *privateKey = [[MYKeychain defaultKeychain] generateRSAKeyPairOfSize: 2048];
    Log(@"Key-pair = { %@, %@ }", privateKey, privateKey.publicKey);
    
    Log(@"...creating cert...");
    
    MYCertificate *cert = MYCertificateCreateSelfSigned(privateKey,
                                                      $dict(
                                                          {@"Common Name", @"waldo"},
                                                          {@"Given Name", @"Waldo"},
                                                          {@"Surname", @"Widdershins"},
                                                          {@"Email Address", @"waldo@example.com"},
                                                          {@"Description", @"Just a fictitious person"},
                                                      ));
    Log(@"Cert = %@", cert);
    CAssert(cert);
    [cert.certificateData writeToFile: @"/tmp/MYCryptoTest.cer" atomically: NO];
    
    Log(@"Cert name = %@", cert.commonName);
    Log(@"Cert email = %@", cert.emailAddresses);
    Log(@"Cert pub key = %@", cert.publicKey);
    CAssertEqual(cert.commonName, @"waldo");
    CAssertEqual(cert.emailAddresses, $array(@"waldo@example.com"));
    CAssertEqual(cert.publicKey.publicKeyDigest, privateKey.publicKeyDigest);
    
    CAssert([[MYKeychain defaultKeychain] addCertificate: cert]);
    
    CAssert([cert setUserTrust: kSecTrustResultProceed]);
}



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
