//
//  MYIdentity.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/9/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCertificate.h"
@class MYPrivateKey;


/** An Identity represents a certificate with an associated private key. */
@interface MYIdentity : MYCertificate
{
    @private
    SecIdentityRef _identityRef;
}

/** Initializes a MYIdentity given an existing SecIdentityRef. */
- (id) initWithIdentityRef: (SecIdentityRef)identityRef;

/** The identity's associated private key. */
@property (readonly) MYPrivateKey *privateKey;

/** Returns the identity that's been set as the preferred one for the given name, or nil. */
+ (MYIdentity*) preferredIdentityForName: (NSString*)name;

/** Registers this identity as the preferred one for the given name,
    for later lookup using +preferredIdentityForName:. */
- (BOOL) makePreferredIdentityForName: (NSString*)name;

@end
