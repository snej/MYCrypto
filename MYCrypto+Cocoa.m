//
//  MYCrypto+Cocoa.m
//  MYCrypto
//
//  Created by Jens Alfke on 4/10/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCrypto+Cocoa.h"
#import "MYCrypto_Private.h"
#import "MYIdentity.h"


@implementation SFChooseIdentityPanel (MYCrypto)


- (NSInteger)my_runModalForIdentities:(NSArray *)identities 
                              message:(NSString *)message
{
    NSMutableArray *identityRefs = $marray();
    for (MYIdentity *ident in identities)
        [identityRefs addObject: (id)ident.identityRef];
    return [self runModalForIdentities: identityRefs message: message];
}

- (void)my_beginSheetForWindow:(NSWindow *)docWindow 
                 modalDelegate:(id)delegate 
                didEndSelector:(SEL)didEndSelector
                   contextInfo:(void *)contextInfo 
                    identities:(NSArray *)identities 
                       message:(NSString *)message
{
    NSMutableArray *identityRefs = $marray();
    for (MYIdentity *ident in identities)
        [identityRefs addObject: (id)ident.identityRef];
    [self beginSheetForWindow:docWindow 
                modalDelegate:delegate 
               didEndSelector:didEndSelector
                  contextInfo:contextInfo 
                   identities:identityRefs
                      message:message];
}

- (MYIdentity*) my_identity {
    return [MYIdentity identityWithIdentityRef: [self identity]];
}

@end
