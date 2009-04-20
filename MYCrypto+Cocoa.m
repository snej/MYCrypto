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
