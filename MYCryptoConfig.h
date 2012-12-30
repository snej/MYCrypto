//
//  MYCryptoConfig.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/5/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/SecBase.h>

/*  The iPhone simulator actually has the Mac OS X security API, not the iPhone one.
    So check which API is installed by looking for a preprocessor symbol that's defined
    only in the OS X version of SecBase.h. */

#ifndef MYCRYPTO_USE_IPHONE_API

#if TARGET_OS_IPHONE //&& !defined(__SEC_TYPES__)
#define MYCRYPTO_USE_IPHONE_API 1
#else
#define MYCRYPTO_USE_IPHONE_API 0
#endif

#endif