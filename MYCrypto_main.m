/*
 *  MYCrypto_main.m
 *  MYCrypto
 *
 *  Created by Jens Alfke on 3/28/09.
 *  Copyright 2009 Jens Alfke. All rights reserved.
 *
 */


#import "Test.h"


int main(int argc, const char **argv) {
#if DEBUG
    if (argc<2) {
        static const char *testArgs[] = {"MYCrypto", "Test_All"};
        argc = 2;
        argv = testArgs;
    }
#endif
    
    RunTestCases(argc,argv);
    return 0;
}
