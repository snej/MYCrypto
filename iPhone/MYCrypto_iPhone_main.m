//
//  main.m
//  MYCrypto-iPhone
//
//  Created by Jens Alfke on 3/30/09.
//  Copyright Jens Alfke 2009. All rights reserved.
//

#import <UIKit/UIKit.h>

int main(int argc, char *argv[]) {
    if (argc<2) {
        static char *testArgs[] = {"MYCrypto", "Test_All"};
        argc = 2;
        argv = testArgs;
    }
    RunTestCases(argc,(const char**)argv);
    
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
    int retVal = UIApplicationMain(argc, argv, nil, nil);
    [pool release];
    return retVal;
}
