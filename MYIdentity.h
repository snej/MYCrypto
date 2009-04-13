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

/** Creates a MYIdentity object for an existing Keychain identity reference. */
+ (MYIdentity*) identityWithIdentityRef: (SecIdentityRef)identityRef;

/** The underlying SecIdentityRef. */
@property (readonly) SecIdentityRef identityRef;

/** The identity's associated private key. */
@property (readonly) MYPrivateKey *privateKey;


/** @name Mac-Only
 *  Functionality not available on iPhone. 
 */
//@{
#if !TARGET_OS_IPHONE

/** Returns the identity that's been set as the preferred one for the given name, or nil. */
+ (MYIdentity*) preferredIdentityForName: (NSString*)name;

/** Registers this identity as the preferred one for the given name,
    for later lookup using +preferredIdentityForName:. */
- (BOOL) makePreferredIdentityForName: (NSString*)name;

#endif
//@}


/** @name Expert
 *  Advanced methods. 
 */
//@{

/** Initializes a MYIdentity given an existing SecIdentityRef. */
- (id) initWithIdentityRef: (SecIdentityRef)identityRef;

//@}

@end
