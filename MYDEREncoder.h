//
//  MYDEREncoder.h
//  MYCrypto
//
//  Created by Jens Alfke on 5/29/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface MYDEREncoder : NSObject
{
    id _rootObject;
    NSMutableData *_output;
    NSError *_error;
}

- (id) initWithRootObject: (id)object;
+ (NSData*) encodeRootObject: (id)rootObject error: (NSError**)outError;

@property (readonly) NSData* output;
@property (readonly, retain) NSError *error;

@end
