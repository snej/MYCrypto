//
//  MYCrypto_iPhoneAppDelegate.h
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright Jens Alfke 2009. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface MYCrypto_iPhoneAppDelegate : NSObject <UIApplicationDelegate> {
    UIWindow *window;
}

@property (nonatomic, retain) IBOutlet UIWindow *window;

@end

