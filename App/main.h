//
//  main.h
//  DNSMonitor
//
//  Created by Patrick Wardle on 10/31/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

#ifndef main_h
#define main_h

@import Foundation;

#import <signal.h>

#import "consts.h"
#import "Extension.h"
#import "LogMonitor.h"

@import Cocoa;
@import OSLog;

/* GLOBALS */
long recordCount = 0;

/* FUNCTION DEFINITIONS */

//print usage
void usage(void);

//get bundle of (real) parent
NSString* getParentBundleID(void);

//start (activate) extension
void startExtension(void (^)(BOOL));

//stop (deactivate) extension
BOOL stopExtension(void);

//prettify JSON
NSString* prettifyJSON(NSString* output);

#endif /* main_h */
