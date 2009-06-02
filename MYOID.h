//
//  MYOID.h
//  MYCrypto
//
//  Created by Jens Alfke on 5/28/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Cocoa/Cocoa.h>


/** An ASN.1 Object-ID, which is a sequence of integer components that define namespaces. */
@interface MYOID : NSObject <NSCopying>
{
    NSData *_data;
}

- (id) initWithComponents: (const UInt32*)components count: (unsigned)componentCount;
- (id) initWithBEREncoding: (NSData*)encoding;
- (NSData*) DEREncoding;

- (const UInt32*) components;
- (unsigned) componentCount;

@end
