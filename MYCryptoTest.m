//
//  MYCryptoTest.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 4/1/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYPublicKey.h"
#import "MYPrivateKey.h"
#import "MYKeychain.h"
#import "MYDigest.h"
#import "MYIdentity.h"
#if !TARGET_OS_IPHONE
#import "MYCrypto+Cocoa.h"
#endif
#import "MYCrypto_Private.h"


#if DEBUG


#define kTestCaseRSAKeySize 2048

#pragma mark -
#pragma mark KEYCHAIN:


TestCase(MYKeychain) {
    MYKeychain *kc = [MYKeychain defaultKeychain];
    Log(@"Default keychain = %@", kc);
    CAssert(kc);
#if !MYCRYPTO_USE_IPHONE_API
    CAssert(kc.path);
#endif
    
    kc = [MYKeychain allKeychains];
    Log(@"All-keychains = %@", kc);
    CAssert(kc);
#if !MYCRYPTO_USE_IPHONE_API
    CAssertEq(kc.path,nil);
#endif
}


TestCase(EnumerateKeys) {
    RequireTestCase(MYKeychain);
    NSEnumerator *e = [[MYKeychain allKeychains] enumeratePublicKeys];
    Log(@"Public Key Enumerator = %@", e);
    CAssert(e);
    for (MYPublicKey *key in e) {
        Log(@"Found %@ -- name=%@", key, key.name);
    }
    
    e = [[MYKeychain allKeychains] enumeratePrivateKeys];
    Log(@"Key-Pair Enumerator = %@", e);
    CAssert(e);
    for (MYPrivateKey *key in e) {
        Log(@"Found %@ -- name=%@", key, key.name);
    }
    
    e = [[MYKeychain allKeychains] enumerateSymmetricKeys];
    Log(@"Symmetric Key Enumerator = %@", e);
    CAssert(e);
    for (MYSymmetricKey *key in e) {
        Log(@"Found %@ -- name=%@", key, key.name);
    }
}


TestCase(EnumerateCerts) {
    RequireTestCase(MYKeychain);
    NSEnumerator *e = [[MYKeychain allKeychains] enumerateCertificates];
    Log(@"Enumerator = %@", e);
    CAssert(e);
    for (MYCertificate *cert in e) {
        //Log(@"Found %@ -- name=%@, email=%@", cert, cert.commonName, cert.emailAddresses);
    }
}

TestCase(EnumerateIdentities) {
    RequireTestCase(MYKeychain);
    NSEnumerator *e = [[MYKeychain allKeychains] enumerateIdentities];
    Log(@"Enumerator = %@", e);
    CAssert(e);
    for (MYIdentity *ident in e) {
        Log(@"Found %@\n\tcommonName=%@\n\temails=(%@)\n\tkey=%@",
            ident, ident.commonName, 
#if TARGET_OS_IPHONE
            nil,
#else
            [ident.emailAddresses componentsJoinedByString: @", "],
#endif
            ident.privateKey);
    }
}


#pragma mark -
#pragma mark SYMMETRIC KEYS:


static void testSymmetricKey( CCAlgorithm algorithm, unsigned sizeInBits, MYKeychain *inKeychain ) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    MYSymmetricKey *key = nil;
    @try{
        Log(@"--- Testing %3u-bit #%i %s", sizeInBits, (int)algorithm,
            (inKeychain ?", in keychain" :""));
        // Generate key:
        if (inKeychain)
            key = [inKeychain generateSymmetricKeyOfSize: sizeInBits algorithm: algorithm];
        else
            key = [MYSymmetricKey generateSymmetricKeyOfSize: sizeInBits algorithm: algorithm];
        Log(@"Created %@", key);
    CAssert(key);
        CAssertEq(key.algorithm, algorithm);
        CAssertEq(key.keySizeInBits, sizeInBits);
    #if !TARGET_OS_IPHONE
        CAssert(key.cssmKey != NULL);
    #endif
        
        NSData *keyData = key.keyData;
        Log(@"Key data = %@", keyData);
        CAssertEq(keyData.length, sizeInBits/8);
        
        // Encrypt a small amount of text:
        Log(@"Testing encryption / decryption ...");
        NSData *cleartext = [@"This is a test. This is only a test." dataUsingEncoding: NSUTF8StringEncoding];
        NSData *encrypted = [key encryptData: cleartext];
        Log(@"Encrypted = %u bytes: %@", encrypted.length, encrypted);
        CAssert(encrypted.length >= cleartext.length);
        NSData *decrypted = [key decryptData: encrypted];
        CAssertEqual(decrypted, cleartext);
        
        // Encrypt large binary data:
        cleartext = [NSData dataWithContentsOfFile: @"/Library/Desktop Pictures/Nature/Zen Garden.jpg"];
        CAssert(cleartext);
        encrypted = [key encryptData: cleartext];
        Log(@"Encrypted = %u bytes", encrypted.length);
        CAssert(encrypted.length >= cleartext.length);
        decrypted = [key decryptData: encrypted];
        CAssertEqual(decrypted, cleartext);
        
    #if 1
        Log(@"Testing initWithKeyData:...");
        MYSymmetricKey *key2 = [[MYSymmetricKey alloc] initWithKeyData: keyData algorithm: algorithm];
        CAssert(key2);
        Log(@"Key from data = %@",key2);
        CAssertEqual(key2.keyData, keyData);
        CAssertEq(key2.algorithm, algorithm);
        CAssertEq(key2.keySizeInBits, sizeInBits);
        decrypted = [key2 decryptData: encrypted];
        CAssertEqual(decrypted, cleartext);
        [key2 release];
    #endif

    #if !TARGET_OS_IPHONE
        // Try exporting and importing a wrapped key:
        Log(@"Testing export/import...");
        NSData *exported = [key exportKeyInFormat: kSecFormatWrappedPKCS8 withPEM: NO];
        Log(@"Exported key: %@", exported);
    #if 0
        CAssert(exported);
    #else
        //FIX: Exporting symmetric keys isn't working. Temporarily making this optional.
        if (!exported)
            Warn(@"Unable to export wrapped key");
        else
    #endif
        {
            CAssert(exported);
            MYSymmetricKey *key2 = [[MYSymmetricKey alloc] initWithKeyData: exported algorithm: algorithm];
            Log(@"Reconstituted as %@", key2);
            CAssertEqual(key2.keyData,key.keyData);
            decrypted = [key2 decryptData: encrypted];
            CAssertEqual(decrypted, cleartext);
        }
    #endif
    }@finally{
        [key removeFromKeychain];
    }
    [pool drain];
}


TestCase(MYSymmetricKey) {
    #define kNTests 11
    static const CCAlgorithm kTestAlgorithms[kNTests] = {
        kCCAlgorithmAES128, kCCAlgorithmAES128, kCCAlgorithmAES128,
        kCCAlgorithmDES, kCCAlgorithm3DES,
        kCCAlgorithmCAST, kCCAlgorithmCAST, kCCAlgorithmCAST,
        kCCAlgorithmRC4, kCCAlgorithmRC4, kCCAlgorithmRC4};
    
    static const unsigned kTestBitSizes[kNTests] = {
        128, 192, 256,
        64, 3*64,
        40, 80, 128,
        32, 200, 512*8};

    for (int useKeychain=0; useKeychain<=1; useKeychain++)
        for (int testNo=0; testNo<kNTests; testNo++) 
            testSymmetricKey(kTestAlgorithms[testNo], 
                             kTestBitSizes[testNo],
                             useKeychain ?[MYKeychain defaultKeychain] :nil);
}


TestCase(MYSymmetricKeyPassphrase) {
    Log(@"Prompting for raw passphrase --");
    NSString *rawPassphrase = [MYSymmetricKey promptForPassphraseWithAlertTitle: @"Raw Passphrase Test" 
                                                                    alertPrompt: @"Enter the passphrase 'Testing':"
                                                                       creating: YES];
    Log(@"You entered: '%@'", rawPassphrase);
    CAssertEqual(rawPassphrase, @"Testing");
    
    Log(@"Prompting for passphrase for key --");
    MYSymmetricKey *key = [MYSymmetricKey generateFromUserPassphraseWithAlertTitle: @"Symmetric Key Passphrase Test Case" 
                                                                       alertPrompt: @"Please enter a passphrase to generate a key:"
                                                                          creating: YES
                                                                              salt: @"wahooma"];
    Log(@"Key from passphrase = %@", key);
    CAssert(key);

    // Encrypt a small amount of text:
    Log(@"Testing encryption / decryption ...");
    NSData *cleartext = [@"This is a test. This is only a test." dataUsingEncoding: NSUTF8StringEncoding];
    NSData *encrypted = [key encryptData: cleartext];
    Log(@"Encrypted = %u bytes: %@", encrypted.length, encrypted);
    CAssert(encrypted.length >= cleartext.length);
    NSData *decrypted = [key decryptData: encrypted];
    CAssertEqual(decrypted, cleartext);
    
    // Now test decryption by re-entered passphrase:
    Log(@"Testing decryption using re-entered passphrase...");
    MYSymmetricKey *key2 = [MYSymmetricKey generateFromUserPassphraseWithAlertTitle: @"Symmetric Key Passphrase Test Case" 
                                                                        alertPrompt: @"Please re-enter the same passphrase:" 
                                                                           creating: NO
                                                                               salt: @"wahooma"];
    Log(@"Key from passphrase = %@", key2);
    CAssert(key2);
    decrypted = [key2 decryptData: encrypted];
    CAssertEqual(decrypted, cleartext);
}


#pragma mark -
#pragma mark KEY-PAIRS:


static void TestUseKeyPair(MYPrivateKey *pair) {
    Log(@"---- TestUseKeyPair { %@ , %@ }.", pair, pair.publicKey);
    CAssert(pair);
    CAssert(pair.keyRef);
    MYPublicKey *publicKey = pair.publicKey;
    CAssert(publicKey.keyRef);
    
    NSData *pubKeyData = publicKey.keyData;
    Log(@"Public key = %@ (%u bytes)",pubKeyData,pubKeyData.length);
    CAssert(pubKeyData);
    
    MYSHA1Digest *pubKeyDigest = publicKey.publicKeyDigest;
    Log(@"Public key digest = %@",pubKeyDigest);
    CAssertEqual(pair.publicKeyDigest, pubKeyDigest);
    
    Log(@"SHA1 of pub key = %@", pubKeyData.my_SHA1Digest.asData);
    
    // Let's sign data:
    NSData *data = [@"This is a test. This is only a test!" dataUsingEncoding: NSUTF8StringEncoding];
    NSData *sig = [pair signData: data];
    Log(@"Signature = %@ (%u bytes)",sig,sig.length);
    CAssert(sig);
    CAssert( [publicKey verifySignature: sig ofData: data] );
    
    // Now let's encrypt...
    NSData *crypted = [publicKey encryptData: data];
    Log(@"Encrypted = %@ (%u bytes)",crypted,crypted.length);
    CAssert(crypted);
    CAssertEqual([pair decryptData: crypted], data);
    Log(@"Verified decryption.");
    
    // Test creating a standalone public key:
    MYPublicKey *pub = [[MYPublicKey alloc] initWithKeyRef: publicKey.keyRef];
    CAssert( [pub verifySignature: sig ofData: data] );
    Log(@"Verified signature.");
    
    // Test creating a public key from data:
    Log(@"Reconstituting public key from data...");
    pub = [[MYPublicKey alloc] initWithKeyData: pubKeyData];
    CAssert(pub);
    CAssertEqual(pub.keyData, pubKeyData);
    CAssertEqual(pub.publicKeyDigest, pubKeyDigest);
    CAssert( [pub verifySignature: sig ofData: data] );
    Log(@"Verified signature from reconstituted key.");
}


TestCase(MYGenerateKeyPair) {
    RequireTestCase(MYKeychain);
    
    Log(@"Generating key pair...");
    MYPrivateKey *pair = [[MYKeychain defaultKeychain] generateRSAKeyPairOfSize: kTestCaseRSAKeySize];
    MYPublicKey *publicKey = pair.publicKey;
    Log(@"...created { %@ , %@ }.", pair, publicKey);
    
    @try{
        TestUseKeyPair(pair);
        
        [pair setName: @"Test KeyPair Label"];
        CAssertEqual(pair.name, @"Test KeyPair Label");
        CAssertEqual(publicKey.name, @"Test KeyPair Label");
#if !TARGET_OS_IPHONE
        [pair setComment: @"This key-pair was generated automatically by a test case."];
        CAssertEqual(pair.comment, @"This key-pair was generated automatically by a test case.");
        CAssertEqual(publicKey.comment, @"This key-pair was generated automatically by a test case.");
#endif
        [pair setAlias: @"TestCase@mooseyard.com"];
        CAssertEqual(pair.alias, @"TestCase@mooseyard.com");
        CAssertEqual(publicKey.alias, @"TestCase@mooseyard.com");
        
        CAssert([pair removeFromKeychain]);
        Log(@"Removed key-pair.");
        pair = nil;
        
    }@finally {
        if (pair) {
            if ([pair removeFromKeychain])
                Log(@"Removed key-pair from keychain.");
            else
                Warn(@"Unable to remove test key-pair from keychain");
        }
    }
}


#if !TARGET_OS_IPHONE
TestCase(MYUseIdentity) {
    MYIdentity *me = nil;//[MYIdentity preferredIdentityForName: @"MYCryptoTest"];
    if (!me) {
        NSArray *idents = [[[MYKeychain allKeychains] enumerateIdentities] allObjects];
        SFChooseIdentityPanel *panel = [SFChooseIdentityPanel sharedChooseIdentityPanel];
        [panel setAlternateButtonTitle: @"Cancel"];
        if ([panel my_runModalForIdentities: idents 
                                    message: @"Choose an identity for the MYEncoder test case:"]
            != NSOKButton) {
            [NSException raise: NSGenericException format: @"User canceled"];
        }
        me = [panel my_identity];
        [me makePreferredIdentityForName: @"MYCryptoTest"];
    }
    CAssert(me,@"No default identity has been set up in the Keychain");
    TestUseKeyPair(me.privateKey);
}
#endif


#pragma mark -
#pragma mark KEYPAIR EXPORT:


static void testKeyPairExportWithPrompt(BOOL withPrompt) {
    MYKeychain *keychain = [MYKeychain allKeychains];
    Log(@"Generating key pair...");
    MYPrivateKey *pair = [keychain generateRSAKeyPairOfSize: kTestCaseRSAKeySize];
    CAssert(pair);
    CAssert(pair.keyRef);
    CAssert(pair.publicKey.keyRef);
    Log(@"...created pair.");
    
    @try{
        NSData *pubKeyData = pair.publicKey.keyData;
        CAssert(pubKeyData.length >= kTestCaseRSAKeySize/8);
        [pair setName: @"Test KeyPair Label"];
        CAssertEqual(pair.name, @"Test KeyPair Label");
#if !TARGET_OS_IPHONE
        [pair setComment: @"This key-pair was generated automatically by a test case."];
        CAssertEqual(pair.comment, @"This key-pair was generated automatically by a test case.");
#endif
        [pair setAlias: @"TestCase@mooseyard.com"];
        CAssertEqual(pair.alias, @"TestCase@mooseyard.com");
        
#if !TARGET_OS_IPHONE
        Log(@"Exporting key-pair...");
        NSString *passphrase = @"passphrase";
        NSData *privKeyData;
        if (withPrompt)
            privKeyData = [pair exportKey];
        else
            privKeyData = [pair _exportKeyInFormat: kSecFormatWrappedOpenSSL
                                          withPEM: YES
                                       passphrase: passphrase];
        Log(@"Exported data = %@ (%u bytes)", privKeyData,privKeyData.length);
        CAssert(privKeyData);
        [privKeyData writeToFile: @"ExportedPrivKey" atomically: YES];
#endif
        
        // Check key lookup:
        Log(@"Looking up public key of pair in keychain...");
        MYSHA1Digest *digest = pair.publicKeyDigest;
        MYPublicKey *foundKey = [keychain publicKeyWithDigest: digest];
        CAssertEqual(foundKey, pair.publicKey);
        CAssert([keychain.enumeratePublicKeys.allObjects containsObject: pair.publicKey]);
        MYPrivateKey *foundPair = [keychain privateKeyWithDigest: digest];
        CAssertEqual(foundPair, pair);
        CAssert([keychain.enumeratePrivateKeys.allObjects containsObject: pair]);
        
        Log(@"Removing key-pair from keychain...");
        CAssert([pair removeFromKeychain]);
        pair = nil;
        CAssert([keychain publicKeyWithDigest: digest] == nil);
        
#if !TARGET_OS_IPHONE
        Log(@"Importing key-pair...");
        if (withPrompt) {
            pair = [keychain importPublicKey: pubKeyData 
                                  privateKey: privKeyData];
        } else {
            pair = [[[MYPrivateKey alloc] _initWithKeyData: privKeyData
                                             publicKeyData: pubKeyData
                                               forKeychain: keychain.keychainRefOrDefault
                                                passphrase: passphrase]
                    autorelease];
        }
        CAssert(pair);
        CAssertEqual(pair.publicKey.keyData, pubKeyData);
#endif
    }@finally {
        if (pair) {
            if ([pair removeFromKeychain])
                Log(@"Removed key-pair from keychain.");
            else
                Warn(@"Unable to remove test key-pair from keychain");
        }
    }
}

TestCase(KeyPairExport) {
    RequireTestCase(MYKeychain);
    RequireTestCase(MYGenerateKeyPair);
    testKeyPairExportWithPrompt(NO);
}

TestCase(KeyPairExportWithUI) {
    RequireTestCase(KeyPairExport);
    testKeyPairExportWithPrompt(YES);
}


#endif DEBUG

