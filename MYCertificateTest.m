//
//  MYCertificateTest.m
//  MYCrypto
//
//  Created by Jens Alfke on 6/15/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCertificateInfo.h"
#import "MYCrypto.h"
#import "MYCrypto_Private.h"


#if DEBUG


static MYCertificateInfo* testCertData(NSData *certData, BOOL selfSigned) {
    //Log(@"Cert Data =\n%@", certData);
    CAssert(certData!=nil);
    NSError *error = nil;
    MYCertificateInfo *pcert = [[MYCertificateInfo alloc] initWithCertificateData: certData 
                                                                            error: &error];
    CAssertNil(error);
    CAssert(pcert != nil);
    
    CAssertEq(pcert.isRoot, selfSigned);
        
    MYCertificateName *subject = pcert.subject;
    Log(@"Common Name = %@", subject.commonName);
    Log(@"Given Name  = %@", subject.givenName);
    Log(@"Surname     = %@", subject.surname);
    Log(@"Desc        = %@", subject.nameDescription);
    Log(@"Email       = %@", subject.emailAddress);
    Log(@"All Emails  = %@", pcert.emailAddresses);

    for (MYOID* oid in pcert.extensionOIDs) {
        BOOL isCritical;
        id value = [pcert extensionForOID:oid isCritical:&isCritical];
        CAssert(value != nil);
        Log(@"Extension %@%@ = %@", oid, (isCritical ?@" (critical)" :@""), value);
    }
    Log(@"Key Usage = 0x%x", pcert.keyUsage);
    Log(@"Extended Key Usage = %@", pcert.extendedKeyUsage);
    Log(@"Subject Alt Name = %@", pcert.subjectAlternativeName);
    
    MYPublicKey *pcertKey = pcert.subjectPublicKey;
    Log(@"Subject Public Key = %@", pcertKey);
    CAssert(pcertKey);
    
    // Now go through MYCertificate:
    Log(@"Creating a MYCertificate from the data...");
    MYCertificate *cert = [[MYCertificate alloc] initWithCertificateData: certData];
    Log(@"MYCertificate = %@", cert);
    CAssert(cert);
    CAssertEqual(cert.info, pcert);
    Log(@"Trust = %@", MYTrustResultDescribe([cert evaluateTrust]));
    
    MYPublicKey *certKey = cert.publicKey;
    Log(@"MYCertificate public key = %@", certKey);
    CAssertEqual(certKey.keyData, pcert.subjectPublicKey.keyData);
    /*TEMP
    Log(@"Adding to keychain...");
    cert = [[MYKeychain defaultKeychain] importCertificate: certData];
    Log(@"Imported as %@", cert);
    //CAssert(cert);
    if (cert) {
        Log(@"Removing from keychain...");
        CAssert([cert removeFromKeychain]);
    }
    */
    return pcert;
}

static NSData* readTestFile(NSString *filename) {
#if TARGET_OS_IPHONE
    filename = [[NSBundle mainBundle] pathForResource: filename ofType: @"cer"];
#else
    filename = [filename stringByAppendingPathExtension: @"cer"];
#endif
    Log(@"--- Testing certificate file %@", filename);
    NSData *data = [NSData dataWithContentsOfFile: filename];
    CAssert(data, @"Couldn't read file %@", filename);
    return data;
}

static MYCertificateInfo* testCert(NSString *filename, BOOL selfSigned) {
    return testCertData(readTestFile(filename), selfSigned);
}


TestCase(ParsedCert) {
    RequireTestCase(ParseCert);
    MYCertificateInfo* pcert = testCert(@"selfsigned_email", YES);
    CAssertEq(pcert.keyUsage, kKeyUsageDigitalSignature | kKeyUsageDataEncipherment);
    CAssertEqual(pcert.extendedKeyUsage, ([NSSet setWithObjects: kExtendedKeyUsageEmailProtectionOID, nil]));
    
    CAssert([pcert allowsKeyUsage:0]);
    CAssert([pcert allowsKeyUsage:kKeyUsageDigitalSignature]);
    CAssert([pcert allowsKeyUsage:kKeyUsageDigitalSignature | kKeyUsageDataEncipherment]);
    CAssert(![pcert allowsKeyUsage:kKeyUsageNonRepudiation]);
    CAssert(![pcert allowsKeyUsage:kKeyUsageNonRepudiation | kKeyUsageDigitalSignature]);

    CAssert([pcert allowsExtendedKeyUsage:[NSSet set]]);
    CAssert([pcert allowsExtendedKeyUsage:[NSSet setWithObject: kExtendedKeyUsageEmailProtectionOID]]);
    CAssert(![pcert allowsExtendedKeyUsage:[NSSet setWithObject: kExtendedKeyUsageServerAuthOID]]);
    CAssert(![pcert allowsExtendedKeyUsage:([NSSet setWithObjects: kExtendedKeyUsageEmailProtectionOID,kExtendedKeyUsageServerAuthOID, nil])]);

    testCert(@"selfsigned", YES);
    testCert(@"iphonedev", NO);
    
    // Now test a self-signed cert with a bad signature:
    MYCertificate *cert = [[MYCertificate alloc] initWithCertificateData: readTestFile(@"selfsigned_altered")];
    Log(@"MYCertificate = %@", cert);
    CAssertNil(cert);
}


#import "MYCrypto_Private.h"

TestCase(CreateCert) {
    RequireTestCase(EncodeCert);
    MYPrivateKey *privateKey = [[MYKeychain defaultKeychain] generateRSAKeyPairOfSize: 512];
    CAssert(privateKey);
    Log(@"---- Generated key-pair with %@, %@", privateKey.publicKey, privateKey);
    MYIdentity *identity = nil;
    @try{
        MYCertificateRequest *pcert = [[MYCertificateRequest alloc] initWithPublicKey: privateKey.publicKey];
        CAssertEqual(pcert.subjectPublicKey.keyData, privateKey.publicKey.keyData);
        
        Log(@"---- Subject names...");
        MYCertificateName *subject = pcert.subject;
        subject.commonName = @"testcase";
        subject.givenName = @"Test";
        subject.surname = @"Case";
        subject.nameDescription = @"Just a test certificate created by MYCrypto";
        subject.emailAddress = @"testcase@example.com";

        subject = pcert.subject;
        CAssertEqual(subject.commonName, @"testcase");
        CAssertEqual(subject.givenName, @"Test");
        CAssertEqual(subject.surname, @"Case");
        CAssertEqual(subject.nameDescription, @"Just a test certificate created by MYCrypto");
        CAssertEqual(subject.emailAddress, @"testcase@example.com");
        
        Log(@"---- Extensions...");
        CAssertEqual(pcert.extensionOIDs, $array());
        CAssertEq(pcert.keyUsage, kKeyUsageUnspecified);
        CAssertEqual(pcert.extendedKeyUsage, nil);
        pcert.keyUsage = kKeyUsageDigitalSignature | kKeyUsageDataEncipherment;
        pcert.extendedKeyUsage = [NSSet setWithObjects: kExtendedKeyUsageServerAuthOID,kExtendedKeyUsageEmailProtectionOID, nil];
        CAssertEq(pcert.keyUsage, kKeyUsageDigitalSignature | kKeyUsageDataEncipherment);
        CAssertEqual(pcert.extendedKeyUsage, ([NSSet setWithObjects: kExtendedKeyUsageServerAuthOID,kExtendedKeyUsageEmailProtectionOID, nil]));
        
        Log(@"---- Signing...");
        NSError *error;
        NSData *certData = [pcert selfSignWithPrivateKey: privateKey error: &error];
        Log(@"Generated cert = \n%@", certData);
        CAssert(certData);
        CAssertNil(error);
        CAssert(certData);
        MYCertificateInfo *pcert2 = testCertData(certData, YES);
        
        Log(@"---- Verifying Info...");
        MYCertificateName *subject2 = pcert2.subject;
        CAssertEqual(subject2,subject);
        CAssertEqual(subject2.commonName, @"testcase");
        CAssertEqual(subject2.givenName, @"Test");
        CAssertEqual(subject2.surname, @"Case");
        CAssertEqual(subject2.nameDescription, @"Just a test certificate created by MYCrypto");
        CAssertEqual(subject2.emailAddress, @"testcase@example.com");
        CAssertEq(pcert2.keyUsage, kKeyUsageDigitalSignature | kKeyUsageDataEncipherment);
        CAssertEqual(pcert2.extendedKeyUsage, ([NSSet setWithObjects: kExtendedKeyUsageServerAuthOID,kExtendedKeyUsageEmailProtectionOID, nil]));

        Log(@"---- Creating MYCertificate object...");
        MYCertificate *cert = [[MYCertificate alloc] initWithCertificateData: certData];
        Log(@"Loaded %@", cert);
        CAssert(cert);
        MYPublicKey *certKey = cert.publicKey;
        Log(@"Its public key has name %@", certKey.name);//TEMP
        Log(@"Its public key = %@", certKey);
        CAssertEqual(certKey.keyData, privateKey.publicKey.keyData);
        Log(@"X.509 trust = %@", MYTrustResultDescribe([cert evaluateTrust]));
        Log(@"SSL trust = %@", MYTrustResultDescribe([cert evaluateTrustWithPolicy: [MYCertificate SSLPolicy]]));
        
        Log(@"---- Adding cert to keychain...");
        MYCertificate *addedCert = [[MYKeychain defaultKeychain] importCertificate: certData];
        Log(@"Imported as %@", addedCert);
        //CAssert(addedCert);
        if (addedCert)
            CAssert([addedCert removeFromKeychain]);
        
        Log(@"---- Creating Identity...");
        identity = [pcert createSelfSignedIdentityWithPrivateKey: privateKey error: &error];
        Log(@"Identity = %@", identity);
        CAssert(identity);
        CAssertNil(error);
        CAssertEqual(identity.keychain, [MYKeychain defaultKeychain]);
        CAssertEqual(identity.privateKey.publicKeyDigest, privateKey.publicKeyDigest);
        CAssert([identity isEqualToCertificate: cert]);
        
    } @finally {
        // [privateKey removeFromKeychain];
        // [identity removeFromKeychain];
        // Currently I'm leaving them in, so the EnumerateXXX tests can chew on them later.
    }
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
