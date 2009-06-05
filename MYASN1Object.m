//
//  MYASN1Object.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 5/28/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

// Reference:
// <http://www.columbia.edu/~ariel/ssleay/layman.html> "Layman's Guide To ASN.1/BER/DER"

#import "MYASN1Object.h"


@implementation MYASN1Object


- (id) initWithTag: (uint32_t)tag
           ofClass: (uint8_t)tagClass 
       constructed: (BOOL)constructed
             value: (NSData*)value
{
    Assert(value);
    self = [super init];
    if (self != nil) {
        _tag = tag;
        _tagClass = tagClass;
        _constructed = constructed;
        _value = [value copy];
    }
    return self;
}

- (id) initWithTag: (uint32_t)tag
           ofClass: (uint8_t)tagClass 
        components: (NSArray*)components
{
    Assert(components);
    self = [super init];
    if (self != nil) {
        _tag = tag;
        _tagClass = tagClass;
        _constructed = YES;
        _components = [components copy];
    }
    return self;
}

- (void) dealloc
{
    [_value release];
    [_components release];
    [super dealloc];
}


@synthesize tag=_tag, tagClass=_tagClass, constructed=_constructed, value=_value, components=_components;


- (NSString*)description {
    if (_components)
        return $sprintf(@"%@[%hhu/%u/%u]%@", self.class, _tagClass,(unsigned)_constructed,_tag, _components);
    else
        return $sprintf(@"%@[%hhu/%u/%u, %u bytes]", self.class, _tagClass,(unsigned)_constructed,_tag, _value.length);
}

- (BOOL) isEqual: (id)object {
    return [object isKindOfClass: [MYASN1Object class]] 
        && _tag==[object tag] 
        && _tagClass==[object tagClass] 
        && _constructed==[object constructed] 
        && $equal(_value,[object value])
        && $equal(_components,[object components]);
}

static void dump(id object, NSMutableString *output, NSString *indent) {
    if ([object isKindOfClass: [MYASN1Object class]]) {
        MYASN1Object *asn1Obj = object;
        [output appendFormat: @"%@%@[%hhu/%u]", indent, asn1Obj.class, asn1Obj.tagClass,asn1Obj.tag];
        if (asn1Obj.components) {
            [output appendString: @":\n"];
            NSString *subindent = [indent stringByAppendingString: @"    "];
            for (id o in asn1Obj.components)
                dump(o,output, subindent);
        } else
            [output appendFormat: @" %@\n", asn1Obj.value];
    } else if([object respondsToSelector: @selector(objectEnumerator)]) {
        [output appendString: indent];
        if ([object isKindOfClass: [NSArray class]])
            [output appendString: @"Sequence:\n"];
        else if ([object isKindOfClass: [NSSet class]])
            [output appendString: @"Set:\n"];
        else
            [output appendFormat: @"%@:\n", [object class]];
        NSString *subindent = [indent stringByAppendingString: @"    "];
        for (id o in object)
            dump(o,output, subindent);
    } else {
        [output appendFormat: @"%@%@\n", indent, object];
    }
}

+ (NSString*) dump: (id)object {
    NSMutableString *output = [NSMutableString stringWithCapacity: 512];
    dump(object,output,@"");
    return output;
}


@end



@implementation MYASN1BigInteger

@end



@implementation MYBitString


- (id)initWithBits: (NSData*)bits count: (unsigned)bitCount {
    Assert(bits);
    Assert(bitCount <= 8*bits.length);
    self = [super init];
    if (self != nil) {
        _bits = [bits copy];
        _bitCount = bitCount;
    }
    return self;
}

+ (MYBitString*) bitStringWithData: (NSData*)bits {
    return [[[self alloc] initWithBits: bits count: 8*bits.length] autorelease];
}

- (void) dealloc
{
    [_bits release];
    [super dealloc];
}

@synthesize bits=_bits, bitCount=_bitCount;

- (NSString*) description {
    return $sprintf(@"%@%@", [self class], _bits);
}

- (unsigned) hash {
    return _bits.hash ^ _bitCount;
}

- (BOOL) isEqual: (id)object {
    return [object isKindOfClass: [MYBitString class]] 
        && _bitCount==[object bitCount] 
        && [_bits isEqual: [object bits]];
}

@end
