//
//  MYKeychainItem.m
//  MYCrypto
//
//  Created by Jens Alfke on 3/26/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKeychainItem.h"
#import "MYCrypto_Private.h"
#import "MYErrorUtils.h"


NSString* const MYCSSMErrorDomain = @"CSSMErrorDomain";


@implementation MYKeychainItem


- (id) initWithKeychainItemRef: (MYKeychainItemRef)itemRef
{
    Assert(itemRef!=NULL);
    self = [super init];
    if (self != nil) {
        _itemRef = itemRef;
        CFRetain(_itemRef);
        LogTo(INIT,@"%@, _itemRef=%@", [self class], itemRef);
    }
    return self;
}


@synthesize keychainItemRef=_itemRef;

- (void) dealloc
{
    if (_itemRef) CFRelease(_itemRef);
    [super dealloc];
}

- (void) finalize
{
    if (_itemRef) CFRelease(_itemRef);
    [super finalize];
}

- (id) copyWithZone: (NSZone*)zone {
    // As keys are immutable, it's not necessary to make copies of them. This makes it more efficient
    // to use instances as NSDictionary keys or store them in NSSets.
    return [self retain];
}

- (BOOL) isEqual: (id)obj {
    return (obj == self) ||
           ([obj isKindOfClass: [MYKeychainItem class]] && CFEqual(_itemRef, [obj keychainItemRef]));
}

- (NSUInteger) hash {
    return CFHash(_itemRef);
}

- (NSString*) description {
    return $sprintf(@"%@[%p]", [self class], _itemRef);     //FIX: Can we do anything better?
}


- (NSArray*) _itemList {
    return $array((id)_itemRef);
}

#if MYCRYPTO_USE_IPHONE_API
- (CFDictionaryRef) asQuery {
    return (CFDictionaryRef) $dict( {(id)kSecClass, (id)kSecClassKey},//FIX
                                    {(id)kSecMatchItemList, self._itemList} );
}
#endif


- (MYKeychain*) keychain {
#if MYCRYPTO_USE_IPHONE_API
    return [MYKeychain defaultKeychain];
#else
    MYKeychain *keychain = nil;
    SecKeychainRef keychainRef = NULL;
    if (check(SecKeychainItemCopyKeychain((SecKeychainItemRef)_itemRef, &keychainRef), @"SecKeychainItemCopyKeychain")) {
        if (keychainRef) {
            keychain = [[[MYKeychain alloc] initWithKeychainRef: keychainRef] autorelease];
            CFRelease(keychainRef);
        }
    }
    return keychain;
#endif
}

- (BOOL) removeFromKeychain {
    OSStatus err;
#if MYCRYPTO_USE_IPHONE_API
    err = SecItemDelete(self.asQuery);
#else
    err = SecKeychainItemDelete((SecKeychainItemRef)_itemRef);
    if (err==errSecInvalidItemRef)
        return YES;     // result for an item that's not in a keychain
#endif
    return err==errSecItemNotFound || check(err, @"SecKeychainItemDelete");
}


#pragma mark -
#pragma mark DATA / METADATA ACCESSORS:


- (NSData*) _getContents: (OSStatus*)outError {
    NSData *contents = nil;
#if MYCRYPTO_USE_IPHONE_API
#else
	UInt32 length = 0;
    void *bytes = NULL;
    *outError = SecKeychainItemCopyAttributesAndData(_itemRef, NULL, NULL, NULL, &length, &bytes);
    if (!*outError && bytes) {
        contents = [NSData dataWithBytes: bytes length: length];
        SecKeychainItemFreeAttributesAndData(NULL, bytes);
    }
#endif
    return contents;
}

+ (NSData*) _getAttribute: (SecKeychainAttrType)attr ofItem: (MYKeychainItemRef)item {
    NSData *value = nil;
#if MYCRYPTO_USE_IPHONE_API
    NSDictionary *info = $dict( {(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecMatchItemList, $array((id)item)},
                                {(id)kSecReturnAttributes, $true} );
    CFDictionaryRef attrs;
    if (!check(SecItemCopyMatching((CFDictionaryRef)info, (CFTypeRef*)&attrs), @"SecItemCopyMatching"))
        return nil;
    CFTypeRef rawValue = CFDictionaryGetValue(attrs,attr);
    value = rawValue ?[[(id)CFMakeCollectable(rawValue) retain] autorelease] :nil;
    CFRelease(attrs);
    
#else
	UInt32 format = kSecFormatUnknown;
	SecKeychainAttributeInfo info = {.count=1, .tag=(UInt32*)&attr, .format=&format};
    SecKeychainAttributeList *list = NULL;
	
    if (check(SecKeychainItemCopyAttributesAndData((SecKeychainItemRef)item, &info,
                                                   NULL, &list, NULL, NULL),
              @"SecKeychainItemCopyAttributesAndData")) {
        if (list) {
            if (list->count == 1)
                value = [NSData dataWithBytes: list->attr->data
                                       length: list->attr->length];
            else if (list->count > 1)
                Warn(@"Multiple values for keychain item attribute");
            SecKeychainItemFreeAttributesAndData(list, NULL);
        }
    }
#endif
    return value;
}

+ (NSString*) _getStringAttribute: (SecKeychainAttrType)attr ofItem: (MYKeychainItemRef)item {
    NSData *value = [self _getAttribute: attr ofItem: item];
    if (!value) return nil;
    const char *bytes = value.bytes;
    size_t length = value.length;
    if (length>0 && bytes[length-1] == 0)
        length--;           // Some values are null-terminated!?
    NSString *str = [[NSString alloc] initWithBytes: bytes length: length
                                           encoding: NSUTF8StringEncoding];
    if (!str)
        Warn(@"MYKeychainItem: Couldn't decode attr value as string");
    return [str autorelease];
}

- (NSString*) stringValueOfAttribute: (SecKeychainAttrType)attr {
    return [[self class] _getStringAttribute: attr ofItem: _itemRef];
}


+ (BOOL) _setAttribute: (SecKeychainAttrType)attr ofItem: (MYKeychainItemRef)item
           stringValue: (NSString*)stringValue
{
#if MYCRYPTO_USE_IPHONE_API
    id value = stringValue ?(id)stringValue :(id)[NSNull null];
    NSDictionary *query = $dict({(id)kSecClass, (id)kSecClassKey},
                                {(id)kSecAttrKeyType, (id)attr},
                                {(id)kSecMatchItemList, $array((id)item)});
    NSDictionary *attrs = $dict({(id)attr, value});
    return check(SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)attrs), @"SecItemUpdate");
    
#else
    NSData *data = [stringValue dataUsingEncoding: NSUTF8StringEncoding];
    SecKeychainAttribute attribute = {.tag=attr, .length=data.length, .data=(void*)data.bytes};
	SecKeychainAttributeList list = {.count=1, .attr=&attribute};
    return check(SecKeychainItemModifyAttributesAndData((SecKeychainItemRef)item, &list, 0, NULL),
                 @"SecKeychainItemModifyAttributesAndData");
#endif
}

- (BOOL) setValue: (NSString*)valueStr ofAttribute: (SecKeychainAttrType)attr {
    return [[self class] _setAttribute: attr ofItem: _itemRef stringValue: valueStr];
}


@end




BOOL check(OSStatus err, NSString *what) {
    if (err) {
#if !MYCRYPTO_USE_IPHONE_API
        if (err < -2000000000)
            return checkcssm(err,what);
#endif
        Warn(@"MYCrypto error, %@: %@", what, MYErrorName(NSOSStatusErrorDomain,err));
        if (err==-50)
            [NSException raise: NSGenericException format: @"%@ failed with paramErr (-50)",what];
        return NO;
    } else
        return YES;
}

#if !MYCRYPTO_USE_IPHONE_API
BOOL checkcssm(CSSM_RETURN err, NSString *what) {
    if (err != CSSM_OK) {
        Warn(@"MYCrypto error, %@: %@", what, MYErrorName(MYCSSMErrorDomain,err));
        return NO;
    } else
        return YES;
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
