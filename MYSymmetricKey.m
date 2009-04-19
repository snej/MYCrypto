//
//  MYSymmetricKey.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYSymmetricKey.h"
#import "MYCryptor.h"
#import "MYCrypto_Private.h"

#if !MYCRYPTO_USE_IPHONE_API

#import <Security/cssmtype.h>


CSSM_ALGORITHMS CSSMFromCCAlgorithm( CCAlgorithm ccAlgorithm ) {
    static const CSSM_ALGORITHMS kCSSMAlgorithms[] = {
        CSSM_ALGID_AES, CSSM_ALGID_DES, CSSM_ALGID_3DES_3KEY, CSSM_ALGID_CAST, CSSM_ALGID_RC4
    };
    if (ccAlgorithm >=0 && ccAlgorithm <= kCCAlgorithmRC4)
        return kCSSMAlgorithms[ccAlgorithm];
    else
        return CSSM_ALGID_NONE;
}

static const char *kCCAlgorithmNames[] = {"AES", "DES", "DES^3", "CAST", "RC4"};


/** Undocumented Security function. Unfortunately this is the only way I can find to create
    a SecKeyRef from a CSSM_KEY. */
extern OSStatus SecKeyCreate(const CSSM_KEY *key, SecKeyRef* keyRef) WEAK_IMPORT_ATTRIBUTE;

static CSSM_KEY* cssmKeyFromData( NSData *keyData, CSSM_ALGORITHMS algorithm,
                                 MYKeychain *keychain);
//static CSSM_ENCRYPT_MODE defaultModeForAlgorithm(CSSM_ALGORITHMS algorithm);
//CSSM_PADDING defaultPaddingForAlgorithm(CSSM_ALGORITHMS algorithm);
static CSSM_DATA makeSalt( id salty, size_t length );
static CSSM_RETURN impExpCreatePassKey(
	const SecKeyImportExportParameters *keyParams,  // required
	CSSM_CSP_HANDLE		cspHand,		// MUST be CSPDL
	BOOL                verifyPhrase,   // use 2nd passphrase textfield for verification?
	CSSM_KEY_PTR		*passKey);	// mallocd and RETURNED


#pragma mark -
@implementation MYSymmetricKey


- (id) _initWithCSSMKey: (CSSM_KEY*)cssmKey {
    SecKeyRef keyRef = NULL;
    if (SecKeyCreate == NULL) {
        // If weak-linked SPI fn no longer exists
        Warn(@"Unable to call SecKeyCreate SPI -- not available");
        [self release];
        return nil;
    }
    if (!check(SecKeyCreate(cssmKey,&keyRef), @"SecKeyCreate")) {
        [self release];
        return nil;
    }
    self = [self initWithKeyRef: keyRef];
    if (self) {
        _ownedCSSMKey = cssmKey;            // (so I'll remember to free it)
    }
    return self;
}


- (id) _initWithKeyData: (NSData*)keyData
              algorithm: (CCAlgorithm)algorithm
             inKeychain: (MYKeychain*)keychain
{
    Assert(algorithm <= kCCAlgorithmRC4);
    Assert(keyData);
    CSSM_KEY *key = cssmKeyFromData(keyData, CSSMFromCCAlgorithm(algorithm), keychain);
    if (!key) {
        [self release];
        return nil;
    }
    return [self _initWithCSSMKey: key];
}

- (id) initWithKeyData: (NSData*)keyData
             algorithm: (CCAlgorithm)algorithm
{
    return [self _initWithKeyData: keyData algorithm: algorithm inKeychain: nil];
}

+ (MYSymmetricKey*) _generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                      algorithm: (CCAlgorithm)algorithm
                                     inKeychain: (MYKeychain*)keychain
{
    Assert(algorithm <= kCCAlgorithmRC4);
    CSSM_KEYATTR_FLAGS flags = CSSM_KEYATTR_EXTRACTABLE;
    if (keychain)
        flags |= CSSM_KEYATTR_PERMANENT; // | CSSM_KEYATTR_SENSITIVE;   //FIX: Re-enable this bit
    else {
        flags |= CSSM_KEYATTR_RETURN_REF;
        keychain = [MYKeychain defaultKeychain]; // establish a context for the key
    }
    CSSM_KEYUSE usage = CSSM_KEYUSE_ANY;
    SecKeyRef keyRef = NULL;
    if (!check(SecKeyGenerate(keychain.keychainRefOrDefault,
                              CSSMFromCCAlgorithm(algorithm),
                              keySizeInBits, 
                              0, usage, flags, NULL, &keyRef),
               @"SecKeyGenerate")) {
        return nil;
    }
    return [[[self alloc] initWithKeyRef: keyRef] autorelease];
}

+ (MYSymmetricKey*) generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                     algorithm: (CCAlgorithm)algorithm {
    return [self _generateSymmetricKeyOfSize: keySizeInBits
                                   algorithm: algorithm
                                  inKeychain: nil];
}

+ (NSString*) promptForPassphraseWithAlertTitle: (NSString*)alertTitle
                                    alertPrompt: (NSString*)prompt
                                        creating: (BOOL)creating
{
    // Ask the user for a passphrase:
    SecKeyImportExportParameters params = {
        .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
        .flags = kSecKeySecurePassphrase,
        .alertTitle = (CFStringRef)alertTitle,
        .alertPrompt = (CFStringRef)prompt,
        .keyUsage = CSSM_KEYUSE_ANY,
        .keyAttributes = CSSM_KEYATTR_EXTRACTABLE
    };
    CSSM_CSP_HANDLE cspHandle = [[MYKeychain defaultKeychain] CSPHandle];
    CSSM_KEY *passphraseKey = NULL;
    if (impExpCreatePassKey(&params, 
                            cspHandle, 
                            creating,
                            &passphraseKey) != CSSM_OK)
        return nil;
    
    MYSymmetricKey *key = [[self alloc] _initWithCSSMKey: passphraseKey];
    NSData *keyData = key.keyData;
    Assert(keyData);
    NSString *passphrase = [[NSString alloc] initWithData: keyData
                                                 encoding: NSUTF8StringEncoding];
    [key release];
    return [passphrase autorelease];
}


#define PKCS5_V2_SALT_LEN		8
#define PKCS5_V2_ITERATIONS		2048
#define PKCS5_V2_DES_IV_SIZE	8

+ (MYSymmetricKey*) generateFromUserPassphraseWithAlertTitle: (NSString*)alertTitle
                                                 alertPrompt: (NSString*)prompt
                                                     creating: (BOOL)creating
                                                        salt: (id)saltObj
{
    MYSymmetricKey *generatedKey = nil;

    // Ask the user for a passphrase:
    SecKeyImportExportParameters params = {
        .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
        .flags = kSecKeySecurePassphrase,
        .alertTitle = (CFStringRef)alertTitle,
        .alertPrompt = (CFStringRef)prompt,
        .keyUsage = CSSM_KEYUSE_ANY,
        .keyAttributes = CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_SENSITIVE
    };
    CSSM_CSP_HANDLE cspHandle = [[MYKeychain defaultKeychain] CSPHandle];
    CSSM_KEY *passphraseKey = NULL;
    if (impExpCreatePassKey(&params, 
                            cspHandle, 
                            creating,
                            &passphraseKey) != CSSM_OK)
        return nil;

    CSSM_DATA saltData = makeSalt(saltObj,PKCS5_V2_SALT_LEN);
    CSSM_CRYPTO_DATA seed = {};
    
    // Now use the secure passphrase to generate a symmetric key:
    CSSM_CC_HANDLE ctx = 0;
    CSSM_ACCESS_CREDENTIALS credentials = {};
    if (checkcssm(CSSM_CSP_CreateDeriveKeyContext(cspHandle,
                                                  CSSM_ALGID_PKCS5_PBKDF2,
                                                  CSSM_ALGID_AES, 128,
                                                  &credentials,
                                                  passphraseKey, 
                                                  PKCS5_V2_ITERATIONS,
                                                  &saltData,
                                                  &seed,
                                                  &ctx),
                  @"CSSM_CSP_CreateDeriveKeyContext")) {
        CSSM_PKCS5_PBKDF2_PARAMS params = {.PseudoRandomFunction=CSSM_PKCS5_PBKDF2_PRF_HMAC_SHA1};
        CSSM_DATA paramData = {.Data=(void*)&params, .Length=sizeof(params)};
        CSSM_KEY *cssmKey = calloc(1,sizeof(CSSM_KEY));
        if (checkcssm(CSSM_DeriveKey(ctx,
                                     &paramData,
                                     CSSM_KEYUSE_ANY,
                                     CSSM_KEYATTR_EXTRACTABLE, //| CSSM_KEYATTR_SENSITIVE, 
                                     NULL, 
                                     NULL, 
                                     cssmKey),
                      @"CSSM_DeriveKey")) {
            generatedKey = [[[self alloc] _initWithCSSMKey: cssmKey] autorelease];
        }
    }
    CSSM_DeleteContext(ctx);
    CSSM_FreeKey(cspHandle, &credentials, passphraseKey, YES);
    return generatedKey;        
}


- (void) dealloc
{
    if(_ownedCSSMKey) 
        CSSM_FreeKey(self.cssmCSPHandle, NULL, _ownedCSSMKey, YES);
    [super dealloc];
}


#if !TARGET_OS_IPHONE
- (NSData*) exportWrappedKeyWithPassphrasePrompt: (NSString*)prompt
{
    // Prompt use for a passphrase to use for the wrapping key:
    MYSymmetricKey *wrappingKey = [MYSymmetricKey 
                                   generateFromUserPassphraseWithAlertTitle: @"Export Key" 
                                   alertPrompt: prompt 
                                   creating: YES
                                   salt: [MYCryptor randomKeyOfLength: PKCS5_V2_SALT_LEN*8]];
    if (!wrappingKey)
        return nil;
    Log(@"Wrapping using %@",wrappingKey);
    
    // Create the context:
    CSSM_ACCESS_CREDENTIALS credentials = {};
    CSSM_CSP_HANDLE cspHandle = self.cssmCSPHandle;
    //CSSM_ALGORITHMS algorithm = wrappingKey.cssmAlgorithm;
    CSSM_CC_HANDLE ctx;
    if (!checkcssm(CSSM_CSP_CreateSymmetricContext(cspHandle,
                                                   wrappingKey.cssmAlgorithm, //CSSM_ALGID_3DES_3KEY_EDE, //algorithm, 
                                                   CSSM_ALGMODE_CBCPadIV8, //defaultModeForAlgorithm(algorithm),
                                                   &credentials, 
                                                   wrappingKey.cssmKey,
                                                   NULL,
                                                   CSSM_PADDING_PKCS7, //defaultPaddingForAlgorithm(algorithm),
                                                   NULL,
                                                   &ctx), 
                   @"CSSM_CSP_CreateSymmetricContext"))
        return nil;
    
    // Now wrap the key:
    NSData *result = nil;
    CSSM_WRAP_KEY wrappedKey = {};
    if (checkcssm(CSSM_WrapKey(ctx, &credentials, self.cssmKey, NULL, &wrappedKey),
                  @"CSSM_WrapKey")) {
        // ...and copy the wrapped key data to the result NSData:
        result = [NSData dataWithBytes: wrappedKey.KeyData.Data length: wrappedKey.KeyData.Length];
        CSSM_FreeKey(cspHandle, &credentials, &wrappedKey, NO);
    }
    // Finally, delete the context
    CSSM_DeleteContext(ctx);
    return result;
}
#endif


- (SecExternalItemType) keyType {
    return kSecItemTypeSessionKey;
}

- (CCAlgorithm) algorithm {
    CSSM_ALGORITHMS cssmAlg;
    cssmAlg = self.cssmKey->KeyHeader.AlgorithmId;
    switch(cssmAlg) {
        case CSSM_ALGID_AES:
            return kCCAlgorithmAES128;
        case CSSM_ALGID_DES:
            return kCCAlgorithmDES;	
        case CSSM_ALGID_3DES_3KEY:
            return kCCAlgorithm3DES;
        case CSSM_ALGID_CAST:
            return kCCAlgorithmCAST;
        case CSSM_ALGID_RC4:
            return kCCAlgorithmRC4;	
        default:
            Warn(@"CSSM_ALGORITHMS #%u doesn't map to any CCAlgorithm", cssmAlg);
            return (CCAlgorithm)-1;
    }
}

- (const char*) algorithmName {
    CCAlgorithm a = self.algorithm;
    if (a >= 0 && a <= kCCAlgorithmRC4)
        return kCCAlgorithmNames[a];
    else
        return "???";
}

- (unsigned) keySizeInBits {
    const CSSM_KEY *key = self.cssmKey;
    Assert(key);
    return key->KeyHeader.LogicalKeySizeInBits;
}


- (NSString*) description {
    return $sprintf(@"%@[%u-bit %s]", [self class], self.keySizeInBits, self.algorithmName);
}


- (NSData*) _cryptData: (NSData*)data operation: (CCOperation)op options: (CCOptions)options
{
    NSData *keyData = self.keyData;
    Assert(keyData, @"Couldn't get key data");
    NSMutableData *output = [NSMutableData dataWithLength: data.length + 256];
    size_t bytesWritten = 0;
    CCCryptorStatus status = CCCrypt(op, self.algorithm, options, 
                                     keyData.bytes, keyData.length, NULL,
                                     data.bytes, data.length, output.mutableBytes, output.length,
                                     &bytesWritten);
    if (status) {
        Warn(@"MYSymmetricKey: CCCrypt returned error %i",status);
        return nil;
    }
    output.length = bytesWritten;
    return output;
}

- (NSData*) encryptData: (NSData*)data {
    return [self _cryptData: data operation: kCCEncrypt options: kCCOptionPKCS7Padding];
}


- (NSData*) decryptData: (NSData*)data {
    return [self _cryptData: data operation: kCCDecrypt options: kCCOptionPKCS7Padding];
}


@end


#pragma mark -


static CSSM_KEY* cssmKeyFromData( NSData *keyData, 
                                 CSSM_ALGORITHMS algorithm,
                                 MYKeychain *keychain ) {
    // Thanks to Jim Murphy for showing the way!
    if (!keychain) keychain = [MYKeychain defaultKeychain];
    CSSM_CC_HANDLE ccHandle;
    if (!checkcssm(CSSM_CSP_CreateSymmetricContext([keychain CSPHandle],
                                                   CSSM_ALGID_NONE, CSSM_ALGMODE_WRAP,
                                                   NULL, NULL, NULL,
                                                   CSSM_PADDING_NONE, NULL,
                                                   &ccHandle), 
                   @"CSSM_CSP_CreateSymmetricContext"))
        return NO;
    
    CSSM_KEY wrappedKey = {
        .KeyHeader = {
            .BlobType = CSSM_KEYBLOB_RAW,
            .Format = CSSM_KEYBLOB_RAW_FORMAT_NONE,
            .AlgorithmId = algorithm,
            .KeyClass = CSSM_KEYCLASS_SESSION_KEY,
            .LogicalKeySizeInBits = keyData.length*8,
            .KeyAttr = CSSM_KEYATTR_EXTRACTABLE,
            .KeyUsage = CSSM_KEYUSE_ANY
        },
        .KeyData = {
            .Data = (void*)keyData.bytes,
            .Length = keyData.length
        }
    };
    
    CSSM_KEY *outKey = calloc(sizeof(CSSM_KEY),1);
    CSSM_DATA desc = {};
    if (!checkcssm(CSSM_UnwrapKey(ccHandle,
                                  NULL,
                                  &wrappedKey,
                                  CSSM_KEYUSE_ANY,
                                  CSSM_KEYATTR_EXTRACTABLE,
                                  NULL,
                                  NULL,
                                  outKey,
                                  &desc),
                   @"CSSM_UnwrapKey")) {
        free(outKey);
        outKey = NULL;
    }
    CSSM_DeleteContext(ccHandle);
    return outKey;
}


// Create salt data of a specific length from an arbitrary NSObject. */
static CSSM_DATA makeSalt( id salty, size_t length ) {
    // Convert to NSData if necessary:
    CAssert(salty!=nil);
    if (![salty isKindOfClass: [NSData class]])
        salty = [[salty description] dataUsingEncoding: NSUTF8StringEncoding];
    // Repeat enough times to fill the desired length:
    NSMutableData *salt = [[salty mutableCopy] autorelease];
    CAssert(salt.length>0);
    while (salt.length < length) {
        [salt appendData: salt];
    }
    // Truncate to length and return it:
    salt.length = length;
    return (CSSM_DATA){.Data=(void*)salt.bytes, .Length=salt.length};
}


#pragma mark -
// Code from Keychain.framework:
#if 0
static CSSM_ENCRYPT_MODE defaultModeForAlgorithm(CSSM_ALGORITHMS algorithm) {
    switch(algorithm) {
        // 8-byte block ciphers
        case CSSM_ALGID_DES:
        case CSSM_ALGID_3DES_3KEY_EDE:
        case CSSM_ALGID_RC5:
        case CSSM_ALGID_RC2:
            return CSSM_ALGMODE_CBCPadIV8; break;
        // 16-byte block ciphers
        case CSSM_ALGID_AES:
            return CSSM_ALGMODE_CBCPadIV8; break;
        // stream ciphers
        case CSSM_ALGID_ASC:
        case CSSM_ALGID_RC4:
            return CSSM_ALGMODE_NONE; break;
        // Unknown
        default:
        	Warn(@"Asked for the default mode for algorithm %d, but don't know that algorithm.\n", algorithm);
            return CSSM_ALGMODE_NONE;
    }
}

CSSM_PADDING defaultPaddingForAlgorithm(CSSM_ALGORITHMS algorithm) {
    switch(algorithm) {
        /* 8-byte block ciphers */
        case CSSM_ALGID_DES:
        case CSSM_ALGID_3DES_3KEY_EDE:
        case CSSM_ALGID_RC5:
        case CSSM_ALGID_RC2:
            return CSSM_PADDING_PKCS5; break;
            /* 16-byte block ciphers */
        case CSSM_ALGID_AES:
            return CSSM_PADDING_PKCS7; break;
            /* stream ciphers */
        case CSSM_ALGID_ASC:
        case CSSM_ALGID_RC4:
            return CSSM_PADDING_NONE; break;
            /* RSA/DSA asymmetric */
        case CSSM_ALGID_DSA:
        case CSSM_ALGID_RSA:
            return CSSM_PADDING_PKCS1; break;
            /* Unknown */
        default:
        	Warn(@"Asked for the default padding mode for %d, but don't know that algorithm.\n", algorithm);
            return CSSM_PADDING_NONE;
    }
}
#endif

#pragma mark -
// Code below was copied from SecImportExportUtils.cpp in Apple's libsecurity_keychain project


/*
 * Given a context specified via a CSSM_CC_HANDLE, add a new
 * CSSM_CONTEXT_ATTRIBUTE to the context as specified by AttributeType,
 * AttributeLength, and an untyped pointer.
 */
static CSSM_RETURN impExpAddContextAttribute(CSSM_CC_HANDLE CCHandle,
	uint32 AttributeType,
	uint32 AttributeLength,
	const void *AttributePtr)
{
	CSSM_CONTEXT_ATTRIBUTE		newAttr;	
	
	newAttr.AttributeType     = AttributeType;
	newAttr.AttributeLength   = AttributeLength;
	newAttr.Attribute.Data    = (CSSM_DATA_PTR)AttributePtr;
	return CSSM_UpdateContextAttributes(CCHandle, 1, &newAttr);
}

/* 
* Add a CFString to a crypto context handle. 
*/
static CSSM_RETURN impExpAddStringAttr(
	CSSM_CC_HANDLE ccHand, 
	CFStringRef str,
	CSSM_ATTRIBUTE_TYPE attrType)
{
	/* CFStrings are passed as external rep in UTF8 encoding by convention */
	CFDataRef outData;
	outData = CFStringCreateExternalRepresentation(NULL,
		str, kCFStringEncodingUTF8,	0);		// lossByte 0 ==> no loss allowed 
	if(outData == NULL) {
		Warn(@"impExpAddStringAttr: bad string format");
		return paramErr;
	}
	
	CSSM_DATA attrData;
	attrData.Data = (uint8 *)CFDataGetBytePtr(outData);
	attrData.Length = CFDataGetLength(outData);
	CSSM_RETURN crtn = impExpAddContextAttribute(ccHand, attrType, sizeof(CSSM_DATA),
		&attrData);
	CFRelease(outData);
	if(crtn) {
		Warn(@"impExpAddStringAttr: CSSM_UpdateContextAttributes error");
	}
	return crtn;
}

/*
 * Generate a secure passphrase key. Caller must eventually CSSM_FreeKey the result. 
 */
static CSSM_RETURN impExpCreatePassKey(
	const SecKeyImportExportParameters *keyParams,  // required
	CSSM_CSP_HANDLE		cspHand,		// MUST be CSPDL
	BOOL                verifyPhrase,   // use 2nd passphrase textfield for verification?
	CSSM_KEY_PTR		*passKey)		// mallocd and RETURNED
{
	CSSM_RETURN crtn;
	CSSM_CC_HANDLE ccHand;
	uint32 verifyAttr;
	CSSM_DATA dummyLabel;
	CSSM_KEY_PTR ourKey = NULL;
	
	Log(@"Generating secure passphrase key");
	ourKey = (CSSM_KEY_PTR)malloc(sizeof(CSSM_KEY));
	if(ourKey == NULL) {
		return memFullErr;
	}
	memset(ourKey, 0, sizeof(CSSM_KEY));
	
	crtn = CSSM_CSP_CreateKeyGenContext(cspHand,
		CSSM_ALGID_SECURE_PASSPHRASE,
		4,				// keySizeInBits must be non zero
		NULL,			// Seed
		NULL,			// Salt
		NULL,			// StartDate
		NULL,			// EndDate
		NULL,			// Params
		&ccHand);
	if(crtn) {
		checkcssm(crtn,@"CSSM_CSP_CreateKeyGenContext");
		return crtn;
	}
	/* subsequent errors to errOut: */
	
	/* additional context attributes specific to this type of key gen */
	CAssert(keyParams != NULL);			// or we wouldn't be here
	if(keyParams->alertTitle != NULL) {
		crtn = impExpAddStringAttr(ccHand, keyParams->alertTitle, 
			CSSM_ATTRIBUTE_ALERT_TITLE);
		if(crtn) {
			goto errOut;
		}
	}
	if(keyParams->alertPrompt != NULL) {
		crtn = impExpAddStringAttr(ccHand, keyParams->alertPrompt, 
			CSSM_ATTRIBUTE_PROMPT);
		if(crtn) {
			goto errOut;
		}
	}
	verifyAttr = verifyPhrase ? 1 : 0;
	crtn = impExpAddContextAttribute(ccHand, CSSM_ATTRIBUTE_VERIFY_PASSPHRASE,
		sizeof(uint32), (const void *)verifyAttr);
	if(crtn) {
		checkcssm(crtn,@"impExpAddContextAttribute");
		goto errOut;
	}

	dummyLabel.Data = (uint8 *)"Secure Passphrase";
	dummyLabel.Length = strlen((char *)dummyLabel.Data);
    
    uint32 keyAttr = keyParams->keyAttributes;
    if (keyAttr & CSSM_KEYATTR_SENSITIVE)
        keyAttr |= CSSM_KEYATTR_RETURN_REF;
    else
        keyAttr |= CSSM_KEYATTR_EXTRACTABLE;

	crtn = CSSM_GenerateKey(ccHand,
        keyParams->keyUsage ?: CSSM_KEYUSE_ANY,
		keyAttr,
		&dummyLabel,
		NULL,			// ACL
		ourKey);
	if(crtn) {
		checkcssm(crtn,@"CSSM_GenerateKey");
	}
errOut:
	CSSM_DeleteContext(ccHand);
	if(crtn == CSSM_OK) {
		*passKey = ourKey;
	}
	else if(ourKey != NULL) {
		free(ourKey);
	}
	return crtn;
}
	

#endif !MYCRYPTO_USE_IPHONE_API
