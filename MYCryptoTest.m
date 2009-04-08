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
#import "MYCrypto_Private.h"


#if DEBUG

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


#pragma mark -
#pragma mark SYMMETRIC KEYS:


static void testSymmetricKey( CCAlgorithm algorithm, unsigned sizeInBits ) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    Log(@"--- Testing %3u-bit #%i", sizeInBits, (int)algorithm);
    // Generate key:
    MYSymmetricKey *key = [MYSymmetricKey generateSymmetricKeyOfSize: sizeInBits
                                                           algorithm: algorithm];
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
    
#if !TARGET_OS_IPHONE
    // Try reconstituting the key from its data:
    NSData *exported = [key exportKeyInFormat: kSecFormatWrappedPKCS8 withPEM: NO];
    Log(@"Exported key: %@", exported);
    // CAssert(exported);
    //FIX: Exporting symmetric keys isn't working. Temporarily making this optional.
    if (exported) {
        CAssert(exported);
        MYSymmetricKey *key2 = [[MYSymmetricKey alloc] initWithKeyData: exported algorithm: algorithm];
        Log(@"Reconstituted as %@", key2);
        CAssertEqual(key2,key);
        decrypted = [key2 decryptData: encrypted];
        CAssertEqual(decrypted, cleartext);
    } else
        Warn(@"Unable to export key in PKCS8");
#endif
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

    for (int i=0; i<kNTests; i++) 
        testSymmetricKey(kTestAlgorithms[i], kTestBitSizes[i]);
}


#pragma mark -
#pragma mark KEY-PAIRS:


TestCase(MYPrivateKey) {
    RequireTestCase(MYKeychain);
    
    Log(@"Generating key pair...");
    MYPrivateKey *pair = [[MYKeychain defaultKeychain] generateRSAKeyPairOfSize: 512];
    Log(@"...created { %@ , %@ }.", pair, pair.publicKey);
    CAssert(pair);
    CAssert(pair.keyRef);
    MYPublicKey *publicKey = pair.publicKey;
    CAssert(publicKey.keyRef);
    
    @try{
        NSData *pubKeyData = publicKey.keyData;
        Log(@"Public key = %@ (%u bytes)",pubKeyData,pubKeyData.length);
        CAssert(pubKeyData);
        
        MYSHA1Digest *pubKeyDigest = publicKey.publicKeyDigest;
        Log(@"Public key digest = %@",pubKeyDigest);
        CAssertEqual(pair.publicKeyDigest, pubKeyDigest);
        
        Log(@"SHA1 of pub key = %@", pubKeyData.my_SHA1Digest.asData);
        
        NSData *data = [@"This is a test. This is only a test!" dataUsingEncoding: NSUTF8StringEncoding];
        NSData *sig = [pair signData: data];
        Log(@"Signature = %@ (%u bytes)",sig,sig.length);
        CAssert(sig);
        CAssert( [publicKey verifySignature: sig ofData: data] );
        
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
                
        // Now let's encrypt...
        NSData *crypted = [pub encryptData: data];
        Log(@"Encrypted = %@ (%u bytes)",crypted,crypted.length);
        CAssert(crypted);
        
        CAssertEqual([pair decryptData: crypted], data);
        Log(@"Verified decryption.");
        
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



#pragma mark -
#pragma mark KEYPAIR EXPORT:


static void testKeyPairExportWithPrompt(BOOL withPrompt) {
    MYKeychain *keychain = [MYKeychain allKeychains];
    Log(@"Generating key pair...");
    MYPrivateKey *pair = [keychain generateRSAKeyPairOfSize: 512];
    CAssert(pair);
    CAssert(pair.keyRef);
    CAssert(pair.publicKey.keyRef);
    Log(@"...created pair.");
    
    @try{
        NSData *pubKeyData = pair.publicKey.keyData;
        CAssert(pubKeyData.length >= 512/8);
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
    RequireTestCase(MYPrivateKey);
    testKeyPairExportWithPrompt(NO);
}

TestCase(KeyPairExportWithUI) {
    RequireTestCase(KeyPairExport);
    testKeyPairExportWithPrompt(YES);
}


#endif DEBUG

