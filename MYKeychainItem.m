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


- (id) initWithKeychainItemRef: (MYKeychainItemRef)itemRef;
{
    Assert(itemRef!=NULL);
    self = [super init];
    if (self != nil) {
        _itemRef = itemRef;
        CFRetain(_itemRef);
    }
    return self;
}


@synthesize keychainItemRef=_itemRef;

- (void) dealloc
{
    if (_itemRef) CFRelease(_itemRef);
    [super dealloc];
}

- (id) copyWithZone: (NSZone*)zone {
    // As keys are immutable, it's not necessary to make copies of them. This makes it more efficient
    // to use instances as NSDictionary keys or store them in NSSets.
    return [self retain];
}

- (BOOL) isEqual: (id)obj {
    // Require the objects to be of the same class, so that a MYPublicKey will not be equal to a
    // MYKeyPair with the same public key.
    return (obj == self) || 
           ([obj class] == [self class] && CFEqual(_itemRef, [obj keychainItemRef]));
}

- (NSUInteger) hash {
    return CFHash(_itemRef);
}

- (NSArray*) _itemList {
    return $array((id)_itemRef);
}

#if USE_IPHONE_API
- (CFDictionaryRef) asQuery {
    return (CFDictionaryRef) $dict( {(id)kSecClass, (id)kSecClassKey},//FIX
                                    {(id)kSecMatchItemList, self._itemList} );
}
#endif


- (MYKeychain*) keychain {
#if USE_IPHONE_API
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
#if USE_IPHONE_API
    return check(SecItemDelete(self.asQuery), @"SecItemDelete");
#else
    return check(SecKeychainItemDelete((SecKeychainItemRef)_itemRef), @"SecKeychainItemDelete");
#endif
}


#pragma mark -
#pragma mark DATA / METADATA ACCESSORS:


- (NSData*) _getContents: (OSStatus*)outError {
    NSData *contents = nil;
#if USE_IPHONE_API
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
#if USE_IPHONE_API
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
#if USE_IPHONE_API
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
#if !USE_IPHONE_API
        if (err < -2000000000)
            return checkcssm(err,what);
#endif
        Warn(@"MYCrypto error, %@: %@", what, MYErrorName(NSOSStatusErrorDomain,err));
        return NO;
    } else
        return YES;
}

#if !USE_IPHONE_API
BOOL checkcssm(CSSM_RETURN err, NSString *what) {
    if (err != CSSM_OK) {
        Warn(@"MYCrypto error, %@: %@", what, MYErrorName(MYCSSMErrorDomain,err));
        return NO;
    } else
        return YES;
}
#endif
