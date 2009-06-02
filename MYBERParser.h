//
//  MYBERParser.h
//  MYCrypto
//
//  Created by Jens Alfke on 6/2/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Cocoa/Cocoa.h>


#define MYASN1ErrorDomain @"MYASN1ErrorDomain"


/** Parses a block of BER-formatted data into an object tree. */
id MYBERParse (NSData *ber, NSError **outError);

NSDateFormatter* MYBERGeneralizedTimeFormatter();
NSDateFormatter* MYBERUTCTimeFormatter();
