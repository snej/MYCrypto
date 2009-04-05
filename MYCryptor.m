//
//  Cryptor.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/21/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCryptor.h"
#import "MYDigest.h"
#import "Test.h"

#if USE_IPHONE_API
#import <Security/SecRandom.h>
#else
#import "MYCrypto_Private.h"
#import "MYKeychain.h"
#import <stdlib.h>
#endif


NSString* const CryptorErrorDomain = @"CCCryptor";

#if !USE_IPHONE_API
static BOOL generateRandomBytes(CSSM_CSP_HANDLE module, uint32_t lengthInBytes, void *dstBytes);
#endif


@interface MYCryptor ()
@property (readwrite, retain) NSError *error;
@end



@implementation MYCryptor


+ (NSData*) randomKeyOfLength: (size_t)length {
    NSParameterAssert(length<100000);
    uint8_t *bytes = malloc(length);
    if (!bytes) return nil;
#if USE_IPHONE_API
    BOOL ok = SecRandomCopyBytes(kSecRandomDefault, length,bytes) >= 0;
#else
    BOOL ok = generateRandomBytes([[MYKeychain defaultKeychain] CSPHandle], length, bytes);
#endif
    if (ok)
        return [NSData dataWithBytesNoCopy: bytes length: length freeWhenDone: YES];
    else {
        free(bytes);
        return nil;
    }
}

+ (NSData*) keyOfLength: (size_t)lengthInBits fromPassphrase: (NSString*)passphrase
{
    size_t lengthInBytes = (lengthInBits + 7)/8;
    MYDigest *digest = [[passphrase dataUsingEncoding: NSUTF8StringEncoding] my_SHA256Digest];
    if (lengthInBytes <= digest.length)
        return [digest.asData subdataWithRange: NSMakeRange(0,lengthInBytes)];
    else
        return nil;
}


- (id) initWithKey: (NSData*)key
         algorithm: (CCAlgorithm)algorithm
         operation: (CCOperation)op {
    self = [super init];
    if (self) {
        NSParameterAssert(key);
        _key = [key copy];
        _operation = op;
        _algorithm = algorithm;
        _options = kCCOptionPKCS7Padding;
    }
    return self;
}

- (id) initEncryptorWithKey: (NSData*)key algorithm: (CCAlgorithm)algorithm {
    return [self initWithKey: key algorithm: algorithm operation: kCCEncrypt];
}

- (id) initDecryptorWithKey: (NSData*)key algorithm: (CCAlgorithm)algorithm {
    return [self initWithKey: key algorithm: algorithm operation: kCCDecrypt];
}

- (void) dealloc
{
    if (_cryptor)
        CCCryptorRelease(_cryptor);
    [_key autorelease];
    [_output autorelease];
    [_outputStream release];
    [super dealloc];
}


@synthesize key=_key, algorithm=_algorithm, options=_options,
    outputStream=_outputStream, error=_error;


- (BOOL) _check: (CCCryptorStatus)status {
    if (status == kCCSuccess)
        return YES;
    else {
        Warn(@"MYCryptor: CCCryptor error %i", status);
        self.error = [NSError errorWithDomain: CryptorErrorDomain code: status userInfo: nil];
        return NO;
    }
}


- (BOOL) _outputBytes: (const void*)bytes length: (size_t)length {
    if (_outputStream) {
        NSInteger written = [_outputStream write: bytes maxLength: length];
        if (written < 0) {
            self.error = _outputStream.streamError;
            if (_error)
                Warn(@"MYCryptor: NSOutputStream error %@", _error);
            else
                [self _check: kMYCryptorErrorOutputStreamChoked];
            return NO;
        } else if (written < length) {
            [self _check: kMYCryptorErrorOutputStreamChoked];
            return NO;
        }
    } else if (length > 0) {
        [_output appendBytes: bytes length: length];
    }
    return YES;
}


- (BOOL) _start {
    if (!_cryptor && !_error) {
        if ([self _check: CCCryptorCreate(_operation, _algorithm, _options,
                                          _key.bytes, _key.length, NULL, &_cryptor)]) {
            _output = [[NSMutableData alloc] initWithCapacity: 1024];
        }
    }
    return !_error;
}


- (BOOL) addBytes: (const void*)bytes length: (size_t)length {
    if (length > 0) {
        NSParameterAssert(bytes!=NULL);
        if(!_error && (_cryptor || [self _start])) {
            size_t outputLength = CCCryptorGetOutputLength(_cryptor,length,false);
            void *output = malloc(outputLength);
            if ([self _check: CCCryptorUpdate(_cryptor, bytes, length,
                                              output, outputLength, &outputLength)]) {
                [self _outputBytes: output length: outputLength];
            }
            free(output);
        }
    }
    return !_error;
}

- (BOOL) addData: (NSData*)data
{
    return [self addBytes: data.bytes length: data.length];
}

- (BOOL) addString: (NSString*)str {
    return [self addData: [str dataUsingEncoding: NSUTF8StringEncoding]];
}


- (BOOL) addFromStream: (NSInputStream*)input
{
    uint8_t inputBuffer[1024];
    size_t avail;
    while (!_error && input.hasBytesAvailable) {
        avail = sizeof(inputBuffer);
        NSInteger nRead = [input read: inputBuffer maxLength: sizeof(inputBuffer)];
        if (nRead < 0) {
            self.error = input.streamError;
            return NO;
        } else if (nRead == 0) {
            break;
        } else if (![self addBytes: inputBuffer length: nRead])
            return NO;
    }
    return YES;
}


- (BOOL) finish
{
    if(!_error && (_cryptor || [self _start])) {
        size_t outputLength = 100; //CCCryptorGetOutputLength(_cryptor,1,true);
        void *output = malloc(outputLength);
        if ([self _check: CCCryptorFinal(_cryptor, output, outputLength, &outputLength)]) {
            [self _outputBytes: output length: outputLength];
        }
        free(output);
    }
    CCCryptorRelease(_cryptor);
    _cryptor = NULL;
    return !_error;
}


- (NSData*) outputData {
    if (_cryptor) [self finish];
    if(_error) {
        [_output release];
        _output = nil;
    }
    return _output;
}

- (NSString*) outputString {
    NSData *output = self.outputData;
    if (output) {
        NSString *str = [[NSString alloc] initWithData: output encoding: NSUTF8StringEncoding];
        return [str autorelease];
    } else
        return nil;
}


// NSStream delegate method
- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)eventCode {
    switch (eventCode) {
        case NSStreamEventHasBytesAvailable:
            [self addFromStream: (NSInputStream*)stream];
            break;
        case NSStreamEventEndEncountered:
            [self finish];
            break;
        case NSStreamEventErrorOccurred:
            if (!_error)
                self.error = stream.streamError;
            break;
        default:
            break;
    }
}



@end




#if !USE_IPHONE_API
static BOOL generateRandomBytes(CSSM_CSP_HANDLE module, uint32_t lengthInBytes, void *dstBytes) {
    // Adapted from code in Keychain.framework's KeychainUtils.m by Wade Tregaskis.
    CSSM_CC_HANDLE ccHandle;
    if (!checkcssm(CSSM_CSP_CreateRandomGenContext(module, CSSM_ALGID_APPLE_YARROW, NULL,
                                                  lengthInBytes, &ccHandle),
                   @"CSSM_CSP_CreateRandomGenContext"))
        return NO;
    CSSM_DATA data = {.Data=dstBytes, .Length=lengthInBytes};
    BOOL ok = checkcssm(CSSM_GenerateRandom(ccHandle, &data), @"CSSM_GenerateRandom");
    CSSM_DeleteContext(ccHandle);
    return ok;
}
#endif




TestCase(MYCryptor) {
    // Encryption:
    NSData *key = [MYCryptor randomKeyOfLength: kCCKeySizeAES256];
    Log(@"Key = %@",key);
    MYCryptor *enc = [[MYCryptor alloc] initEncryptorWithKey: key algorithm: kCCAlgorithmAES128];
    CAssert(enc);
    CAssert([enc addString: @"This is a test. "]);
    CAssert([enc addString: @"This is only a test."]);
    CAssertEqual(enc.error, nil);
    NSData *encrypted = enc.outputData;
    CAssertEqual(enc.error, nil);
    CAssert(encrypted.length > 0);
    [enc release];
    Log(@"Encrypted = %@", encrypted);
    
    // Decryption:
    MYCryptor *dec = [[MYCryptor alloc] initDecryptorWithKey: key algorithm: kCCAlgorithmAES128];
    CAssert(dec);
    CAssert([dec addData: encrypted]);
    NSString *decrypted = dec.outputString;
    CAssertEqual(dec.error, nil);
    [dec release];
    Log(@"Decrypted = '%@'", decrypted);
    CAssertEqual(decrypted, @"This is a test. This is only a test.");
    
    // Encryption to stream:
    key = [MYCryptor randomKeyOfLength: kCCKeySizeAES256];
    Log(@"Key = %@",key);
    enc = [[MYCryptor alloc] initEncryptorWithKey: key algorithm: kCCAlgorithmAES128];
    CAssert(enc);
    enc.outputStream = [NSOutputStream outputStreamToMemory];
    [enc.outputStream open];
    CAssert([enc addString: @"This is a test. "]);
    CAssert([enc addString: @"This is only a test."]);
    CAssert([enc finish]);
    CAssertEqual(enc.error, nil);
    encrypted = [[enc.outputStream propertyForKey: NSStreamDataWrittenToMemoryStreamKey] retain];
    CAssert(encrypted.length > 0);
    [enc release];
    Log(@"Encrypted = %@", encrypted);
    
    dec = [[MYCryptor alloc] initDecryptorWithKey: key algorithm: kCCAlgorithmAES128];
    CAssert(dec);
    dec.outputStream = [NSOutputStream outputStreamToMemory];
    [dec.outputStream open];
    CAssert([dec addData: encrypted]);
    CAssert([dec finish]);
    CAssertEqual(dec.error, nil);
    NSData *decryptedData = [dec.outputStream propertyForKey: NSStreamDataWrittenToMemoryStreamKey];
    [dec release];
    decrypted = [[NSString alloc] initWithData: decryptedData
                                                      encoding: NSUTF8StringEncoding];
    Log(@"Decrypted = '%@'", decrypted);
    CAssertEqual(decrypted, @"This is a test. This is only a test.");
    [encrypted release];
    [decrypted release];
}