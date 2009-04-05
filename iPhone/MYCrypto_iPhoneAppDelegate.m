//
//  MYCrypto_iPhoneAppDelegate.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright Jens Alfke 2009. All rights reserved.
//

#import "MYCrypto_iPhoneAppDelegate.h"
#import "MYErrorUtils.h"


@implementation MYCrypto_iPhoneAppDelegate

@synthesize window;


- (void)applicationDidFinishLaunching:(UIApplication *)application {    

    // Override point for customization after application launch
    [window makeKeyAndVisible];
    
    static const char *testArgs[] = {"MYCrypto", "Test_All"};
    int argc = 2;
    const char **argv = testArgs;
    RunTestCases(argc,argv);
}


- (void)dealloc {
    [window release];
    [super dealloc];
}


@end
