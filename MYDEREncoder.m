//
//  MYDEREncoder.m
//  MYCrypto
//
//  Created by Jens Alfke on 5/29/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYDEREncoder.h"
#import "MYASN1Object.h"
#import "MYBERParser.h"
#import "MYOID.h"
#import "MYErrorUtils.h"


#define MYDEREncoderException @"MYDEREncoderException"


@interface MYDEREncoder ()
- (void) _encode: (id)object;
@property (retain) NSError *error;
@end


@implementation MYDEREncoder


- (id) initWithRootObject: (id)rootObject
{
    self = [super init];
    if (self != nil) {
        _rootObject = [rootObject retain];
    }
    return self;
}

+ (NSData*) encodeRootObject: (id)rootObject error: (NSError**)outError {
    MYDEREncoder *encoder = [[self alloc] initWithRootObject: rootObject];
    NSData *output = [encoder.output copy];
    if (outError) *outError = [[encoder.error retain] autorelease];
    [encoder release];
    return [output autorelease];
}

- (void) dealloc
{
    [_rootObject release];
    [_output release];
    [super dealloc];
}



static unsigned sizeOfUnsignedInt (UInt64 n) {
    unsigned bytes = 0;
    for (; n; n >>= 8)
        bytes++;
    return bytes;
}

static unsigned encodeUnsignedInt (UInt64 n, UInt8 buf[], BOOL padHighBit) {
    unsigned size = MAX(1U, sizeOfUnsignedInt(n));
    UInt64 bigEndian = NSSwapHostLongLongToBig(n);
    const UInt8* src = (UInt8*)&bigEndian + (8-size);
    UInt8 *dst = &buf[0];
    if (padHighBit && (*src & 0x80)) {
        *dst++ = 0;
        size++;
    }
    memcpy(dst, src, size);
    return size;
}

static unsigned encodeSignedInt (SInt64 n, UInt8 buf[]) {
    if (n >= 0)
        return encodeUnsignedInt(n, buf, YES);
    else {
        unsigned size = MAX(1U, sizeOfUnsignedInt(~n));
        UInt64 bigEndian = NSSwapHostLongLongToBig(n);
        const UInt8* src = (UInt8*)&bigEndian + (8-size);
        UInt8 *dst = &buf[0];
        if (!(*src & 0x80)) {
            *dst++ = 0xFF;
            size++;
        }
        memcpy(dst, src, size);
        return size;
    }
}


- (void) _writeTag: (unsigned)tag
             class: (unsigned)tagClass
       constructed: (BOOL) constructed
            length: (size_t)length 
{
    struct {
        unsigned tag            :5;
        unsigned isConstructed  :1;
        unsigned tagClass       :2;
        unsigned length         :7;
        unsigned isLengthLong   :1;
        UInt8    extraLength[9];
    } header;
    size_t headerSize = 2;
    
    header.tag = tag;
    header.isConstructed = constructed;
    header.tagClass = tagClass;
    if (length < 128) {
        header.isLengthLong = NO;
        header.length = length;
    } else {
        header.isLengthLong = YES;
        header.length = encodeUnsignedInt(length, header.extraLength, NO);
        headerSize += header.length;
    }
    [_output appendBytes: &header length: headerSize];
}

- (void) _writeTag: (unsigned)tag
             class: (unsigned)tagClass
       constructed: (BOOL) constructed
             bytes: (const void*)bytes 
            length: (size_t)length 
{
    [self _writeTag: tag class: tagClass constructed: constructed length: length];
    [_output appendBytes: bytes length: length];
}

- (void) _writeTag: (unsigned)tag
             class: (unsigned)tagClass
       constructed: (BOOL) constructed
              data: (NSData*)data 
{
    Assert(data);
    [self _writeTag: tag class: tagClass constructed: constructed bytes: data.bytes length: data.length];
}


- (void) _encodeNumber: (NSNumber*)number {
    // Special-case detection of booleans by pointer equality, because otherwise they appear
    // identical to 0 and 1:
    if (number==$true || number==$false) {
        UInt8 value = number==$true ?0xFF :0x00;
        [self _writeTag: 1 class: 0 constructed: NO bytes: &value length: 1];
        return;
    }
    
    const char *type = number.objCType;
    if (strlen(type) == 1) {
        switch(type[0]) {
            case 'c':
            case 'i':
            case 's':
            case 'l':
            case 'q':
            {   // Signed integers:
                UInt8 buf[9];
                size_t size = encodeSignedInt(number.longLongValue, buf);
                [self _writeTag: 2 class: 0 constructed: NO bytes: buf length: size];
                return;
            }
            case 'C':
            case 'I':
            case 'S':
            case 'L':
            case 'Q':
            {   // Unsigned integers:
                UInt8 buf[9];
                size_t size = encodeUnsignedInt(number.unsignedLongLongValue, buf, YES);
                [self _writeTag: 2 class: 0 constructed: NO bytes: buf length: size];
                return;
            }
            case 'B':
            {   // bool
                UInt8 value = number.boolValue ?0xFF :0x00;
                [self _writeTag: 1 class: 0 constructed: NO bytes: &value length: 1];
                return;
            }
        }
    }
    [NSException raise: MYDEREncoderException format: @"Can't DER-encode value %@ (typecode=%s)", number,type];
}


- (void) _encodeString: (NSString*)string {
    NSData *data = [string dataUsingEncoding: NSASCIIStringEncoding];
    if (data)
        [self _writeTag: 19 class: 0 constructed: NO data: data];
    else
        [self _writeTag: 12 class: 0 constructed: NO data: [string dataUsingEncoding: NSUTF8StringEncoding]];
}


- (void) _encodeBitString: (MYBitString*)bitString {
    NSUInteger bitCount = bitString.bitCount;
    [self _writeTag: 3 class: 0 constructed: NO length: 1 + (bitCount/8)];
    UInt8 unused = (8 - (bitCount % 8)) % 8;
    [_output appendBytes: &unused length: 1];
    [_output appendBytes: bitString.bits.bytes length: bitCount/8];
}

- (void) _encodeDate: (NSDate*)date {
    NSString *dateStr = [MYBERGeneralizedTimeFormatter() stringFromDate: date];
    Log(@"Encoded %@ as '%@'",date,dateStr);//TEMP
    [self _writeTag: 24 class: 0 constructed: NO data: [dateStr dataUsingEncoding: NSASCIIStringEncoding]];
}


- (void) _encodeCollection: (id)collection tag: (unsigned)tag class: (unsigned)tagClass {
    MYDEREncoder *subEncoder = [[[self class] alloc] init];
    for (id object in collection)
        [subEncoder _encode: object];
    [self _writeTag: tag class: tagClass constructed: YES data: subEncoder.output];
    [subEncoder release];
}


- (void) _encode: (id)object {
    if (!_output)
        _output = [[NSMutableData alloc] initWithCapacity: 1024];
    if ([object isKindOfClass: [NSNumber class]]) {
        [self _encodeNumber: object];
    } else if ([object isKindOfClass: [NSData class]]) {
        [self _writeTag: 4 class: 0 constructed: NO data: object];
    } else if ([object isKindOfClass: [MYBitString class]]) {
        [self _encodeBitString: object];
    } else if ([object isKindOfClass: [NSString class]]) {
        [self _encodeString: object];
    } else if ([object isKindOfClass: [NSDate class]]) {
        [self _encodeDate: object];
    } else if ([object isKindOfClass: [NSNull class]]) {
        [self _writeTag: 5 class: 0 constructed: NO bytes: NULL length: 0];
    } else if ([object isKindOfClass: [NSArray class]]) {
        [self _encodeCollection: object tag: 16 class: 0];
    } else if ([object isKindOfClass: [NSSet class]]) {
        [self _encodeCollection: object tag: 17 class: 0];
    } else if ([object isKindOfClass: [MYOID class]]) {
        [self _writeTag: 6 class: 0 constructed: NO data: [object DEREncoding]];
    } else if ([object isKindOfClass: [MYASN1Object class]]) {
        MYASN1Object *asn = object;
        if (asn.components)
            [self _encodeCollection: asn.components tag: asn.tag class: asn.tagClass];
        else
            [self _writeTag: asn.tag 
                      class: asn.tagClass
                constructed: asn.constructed
                       data: asn.value];
    } else {
        [NSException raise: MYDEREncoderException format: @"Can't DER-encode a %@", [object class]];
    }
}


- (NSData*) output {
    if (!_output && !_error) {
        @try{
            [self _encode: _rootObject];
        }@catch (NSException *x) {
            if ($equal(x.name, MYDEREncoderException)) {
                self.error = MYError(2,MYASN1ErrorDomain, @"%@", x.reason);
                return nil;
            } else
                @throw(x);
        }
    }
    return _output;
}

@synthesize error=_error;


@end



#define $data(BYTES...)    ({const uint8_t bytes[] = {BYTES}; [NSData dataWithBytes: bytes length: sizeof(bytes)];})

TestCase(DEREncoder) {
    CAssertEqual([MYDEREncoder encodeRootObject: [NSNull null] error: nil],
                 $data(0x05, 0x00));
    CAssertEqual([MYDEREncoder encodeRootObject: $true error: nil],
                 $data(0x01, 0x01, 0xFF));
    CAssertEqual([MYDEREncoder encodeRootObject: $false error: nil],
                 $data(0x01, 0x01, 0x00));

    // Integers:
    CAssertEqual([MYDEREncoder encodeRootObject: $object(0) error: nil],
                 $data(0x02, 0x01, 0x00));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(1) error: nil],
                 $data(0x02, 0x01, 0x01));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(-1) error: nil],
                 $data(0x02, 0x01, 0xFF));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(72) error: nil],
                  $data(0x02, 0x01, 0x48));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(-128) error: nil],
                 $data(0x02, 0x01, 0x80));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(128) error: nil],
                 $data(0x02, 0x02, 0x00, 0x80));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(255) error: nil],
                 $data(0x02, 0x02, 0x00, 0xFF));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(-256) error: nil],
                 $data(0x02, 0x02, 0xFF, 0x00));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(12345) error: nil],
                 $data(0x02, 0x02, 0x30,0x39));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(-12345) error: nil],
                 $data(0x02, 0x02, 0xCF, 0xC7));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(123456789) error: nil],
                 $data(0x02, 0x04, 0x07, 0x5B, 0xCD, 0x15));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(-123456789) error: nil],
                 $data(0x02, 0x04, 0xF8, 0xA4, 0x32, 0xEB));
    CAssertEqual([MYDEREncoder encodeRootObject: $object(-123456789) error: nil],
                 $data(0x02, 0x04, 0xF8, 0xA4, 0x32, 0xEB));

    // Strings:
    CAssertEqual([MYDEREncoder encodeRootObject: @"hello" error: nil],
                 $data(0x13, 0x05, 'h', 'e', 'l', 'l', 'o'));
    CAssertEqual([MYDEREncoder encodeRootObject: @"thérè" error: nil],
                 $data(0x0C, 0x07, 't', 'h', 0xC3, 0xA9, 'r', 0xC3, 0xA8));
    
    // Dates:
    CAssertEqual([MYDEREncoder encodeRootObject: [NSDate dateWithTimeIntervalSinceReferenceDate: 265336576]
                                          error: nil],
                 $data(0x18, 0x0F, '2', '0', '0', '9', '0', '5', '3', '0', '0', '0', '3', '6', '1', '6', 'Z'));

    // Sequences:
    CAssertEqual([MYDEREncoder encodeRootObject: $array($object(72), $true) error: nil],
                 $data(0x30, 0x06,  0x02, 0x01, 0x48,  0x01, 0x01, 0xFF));
    CAssertEqual([MYDEREncoder encodeRootObject: $array( $array($object(72), $true), 
                                                         $array($object(72), $true))
                                          error: nil],
                 $data(0x30, 0x10,  
                       0x30, 0x06,  0x02, 0x01, 0x48,  0x01, 0x01, 0xFF,
                       0x30, 0x06,  0x02, 0x01, 0x48,  0x01, 0x01, 0xFF));
}


TestCase(EncodeCert) {
    NSError *error = nil;
    NSData *cert = [NSData dataWithContentsOfFile: @"../../Tests/selfsigned.cer"];  //TEMP
    id certObjects = MYBERParse(cert,&error);
    CAssertNil(error);
    Log(@"Decoded as:\n%@", [MYASN1Object dump: certObjects]);
    NSData *encoded = [MYDEREncoder encodeRootObject: certObjects error: &error];
    CAssertNil(error);
    id reDecoded = MYBERParse(encoded, &error);
    CAssertNil(error);
    Log(@"Re-decoded as:\n%@", [MYASN1Object dump: reDecoded]);
    [encoded writeToFile: @"../../Tests/selfsigned_reencoded.cer" atomically: YES];
    CAssertEqual(encoded,cert);
}
