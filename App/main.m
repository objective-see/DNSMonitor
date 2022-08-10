//
//  main.m
//  DNSMonitor
//
//  Created by Patrick Wardle on 8/1/22.
//  Copyright (c) 2020 Objective-See. All rights reserved.
//

@import Foundation;
#include <signal.h>

#import "consts.h"
#import "Extension.h"
#import "LogMonitor.h"

@import Cocoa;
@import OSLog;

void startExtension(void (^)(BOOL));

//load the extension
// will generate popup for user that they must approve
void startExtension(void (^reply)(BOOL))
{
    //extension
    Extension* extension = nil;

    //init extension object
    extension = [[Extension alloc] init];
    
    //kick off extension activation request
    [extension toggleExtension:ACTION_ACTIVATE reply:^(BOOL started) {
        
        //once this is started
        //make request to start network extension
        if(YES == started)
        {
            //start
            [extension startNetworkExtension:^(BOOL started) {
                
                //reply
                reply(started);
                
            }];
        }
             
    }];
    
    return;
    
}

//stop extension
BOOL stopExtension(void)
{
    //flag
    __block BOOL wasStopped = NO;
    
    //extension
    Extension* extension = nil;
    
    //wait semaphore
    dispatch_semaphore_t semaphore = 0;
    
    //init extension object
    extension = [[Extension alloc] init];
    
    //init wait semaphore
    semaphore = dispatch_semaphore_create(0);
    
    //kick off extension deactivation request
    [extension toggleExtension:ACTION_DEACTIVATE reply:^(BOOL toggled)
    {
        //error
        // user likely cancelled
        if(YES != toggled)
        {
            //err msg
            NSLog(@"ERROR: failed to deactivate System Extension");
        }
        //happy
        else
        {
            //dbg msg
            NSLog(@"deactived System Extension");
            
            //happy
            wasStopped = YES;
        }
        
        //signal semaphore
        dispatch_semaphore_signal(semaphore);
        
    }];
    
    //wait for extension semaphore
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    
    return wasStopped;
}

//get bundle of (real) parent
NSString* getParentBundleID(void)
{
    //temp
    long long temp = 0;
    
    //parent
    NSString* parentBundleID = nil;
    
    //psn
    ProcessSerialNumber psn = { kNoProcess, kNoProcess };
    
    //process info
    NSDictionary* processInfo = nil;
    
    //get psn of self
    if(noErr != GetProcessForPID(getpid(), &psn))
    {
        //bail
        goto bail;
    }
    processInfo =
    CFBridgingRelease(ProcessInformationCopyDictionary(&psn,kProcessDictionaryIncludeAllInformationMask));
        
    //extract parents PSN
    temp = [[processInfo objectForKey:@"ParentPSN"] longLongValue];
    
    //(re)init psn
    // this time with parent
    psn.highLongOfPSN = (temp >> 32) & 0x00000000FFFFFFFFLL;
    psn.lowLongOfPSN = (temp >> 0) & 0x00000000FFFFFFFFLL;
    
    //(re)init process info
    // this time with parent
    processInfo = CFBridgingRelease(ProcessInformationCopyDictionary(&psn,kProcessDictionaryIncludeAllInformationMask));
    
    //extract bundle ID
    parentBundleID = processInfo[@"CFBundleIdentifier"];
    
bail:
    
    return parentBundleID;
    
}

//main interface
// start extension and dump msg stdout
int main(int argc, const char * argv[]) {
    
    //status
    int status = 0;
    
    //dispatch source
    dispatch_source_t source = 0;
    
    //pool
    @autoreleasepool {
        
        //parent
        NSString* parent = nil;
        
        //log monitor
        LogMonitor* logMonitor = nil;
        
        //log predicate
        NSPredicate* predicate = nil;
        
        //get parent
        parent = getParentBundleID();
        
        //dbg msg
        NSLog(@"started %s (pid: %d, parent: %@) ", BUNDLE_ID, getpid(), parent);
        
        //CHECK 0x1:
        // must be launched via Terminal (or iTerm)
        // if launched via Finder, Dock etc, show main app logic
        // ...which instructs user how to run to run via Terminal
        if( (YES == [parent isEqualTo:@"com.apple.dock"]) ||
            (YES == [parent isEqualTo:@"com.apple.finder"]) )
        {
            //main app
            return NSApplicationMain(argc, argv);
        }
        
        //CHECK 0x2:
        // must be run from /Applications as we're using a System Extension
        if(YES != [NSBundle.mainBundle.bundlePath isEqualToString:[@"/Applications" stringByAppendingPathComponent:APP_NAME]])
        {
            //set
            status = -1;
            
            //err msg
            NSLog(@"\n\nERROR: As %@ uses a System Extension, Apple requires it must be located in /Applications\n\n", [APP_NAME stringByDeletingPathExtension]);
            
            goto bail;
        }
    
        //init predicate to capture log message from extension
        predicate = [NSPredicate predicateWithFormat:@"subsystem='com.objective-see.dnsmonitor'"];
        
        //init log monitor
        logMonitor = [[LogMonitor alloc] init];
        
        //start log monitor
        [logMonitor start:predicate level:Log_Level_Info|Log_Level_Debug eventHandler:^(OSLogEventProxy* event) {
            
            //dbg msg from extension
            NSLog(@"%@", event.composedMessage);
            
        }];
        
        //ignore SIGINT
        // as we implement our own to unload the ext
        signal(SIGINT, SIG_IGN);
        
        //create dispatch handler for SIGINT
        source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
        
        //handle SIGINT
        // stop (deactivate extension)
        dispatch_source_set_event_handler(source, ^{
            
            //stop
            stopExtension();
            
            //bye!
            exit(0);
            
        });
        
        //resume
        dispatch_resume(source);
        
        //start extension
        startExtension(^(BOOL started){
        
            //error?
            if(YES != started)
            {
                //dbg msg
                NSLog(@"ERROR: failed to start System/Network Extension");
                
                //bye
                exit(-1);
            }
            
        });
        
        //run
        // cmd+c to quit
        [NSRunLoop.currentRunLoop run];
    }
    
bail:
    
    return status;
}
