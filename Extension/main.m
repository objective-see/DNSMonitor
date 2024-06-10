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
#import "Process.h"

/* GLOBALS */

//log handle
os_log_t logHandle = nil;

//args
// have to get this from app
NSMutableArray* appArgs = nil;

#import <dns_util.h>

//main
int main(int argc, char *argv[])
{
    //pool
    @autoreleasepool {
        
    //launcher app
    pid_t application = -1;
        
    //init log
    logHandle = os_log_create(BUNDLE_ID, "extension");
        
    //find app
    application = findProcess([APP_NAME stringByDeletingPathExtension]);
    if(-1 == application)
    {
        os_log(logHandle, "application not found ...maybe running in 'do not unload mode'");
    }
    else
    {
        //get args of application
        appArgs = getArgs(application);
    }
    
    //dbg msg
    if(YES != [appArgs containsObject:ARGS_JSON])
    {
        os_log(logHandle, "extension loaded!");
    }

    //start sysext
    // Apple notes, "call [this] as early as possible"
    [NEProvider startSystemExtensionMode];
            
    //dbg msg
    if(YES != [appArgs containsObject:ARGS_JSON])
    {
        os_log(logHandle, "successfully enabled extension ('startSystemExtensionMode' was called)");
    }
    
    }//pool
     
    dispatch_main();
               
bail:
    
    return 0;
}

