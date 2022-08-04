//
//  main.m
//  DNSMonitor (Extension)
//
//  Created by Patrick Wardle on 8/1/22.
//
//  Copyright (c) 2020 Objective-See. All rights reserved.
//

//FOR LOGGING:
// % log stream --level debug --predicate="subsystem='com.objective-see.dnsmonitor'"


@import OSLog;
@import Foundation;
@import NetworkExtension;

#import "consts.h"

/* GLOBALS */

//log handle
os_log_t logHandle = nil;

//main
int main(int argc, char *argv[])
{
    //pool
    @autoreleasepool {
    
    //init log
    logHandle = os_log_create(BUNDLE_ID, "extension");
        
    //dbg msg
    os_log_debug(logHandle, "started: %{public}@ (pid: %d / uid: %d)", NSProcessInfo.processInfo.arguments.firstObject, getpid(), getuid());
    
    //start sysext
    // Apple notes, "call [this] as early as possible"
    [NEProvider startSystemExtensionMode];
        
    //dbg msg
    os_log_debug(logHandle, "enabled extension ('startSystemExtensionMode' was called)");
    
    }//pool
     
    
    
    dispatch_main();
               
bail:
    
    return 0;
}
