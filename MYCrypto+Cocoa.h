//
//  MYCrypto+Cocoa.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/10/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <SecurityInterface/SFChooseIdentityPanel.h>
@class MYIdentity;


@interface SFChooseIdentityPanel (MYCrypto)

- (NSInteger)my_runModalForIdentities:(NSArray *)myIdentitObjects
                              message:(NSString *)message;

- (void)my_beginSheetForWindow:(NSWindow *)docWindow 
                 modalDelegate:(id)delegate 
                didEndSelector:(SEL)didEndSelector
                   contextInfo:(void *)contextInfo 
                    identities:(NSArray *)myIdentitObjects 
                       message:(NSString *)message;

- (MYIdentity*) my_identity;

@end
