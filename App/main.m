//
//  main.m
//  DNSMonitor
//
//  Created by Patrick Wardle on 8/1/22.
//  Copyright (c) 2020 Objective-See. All rights reserved.
//

#import "main.h"

//main interface
// start extension
// ...then dump all msgs to stdout
int main(int argc, const char * argv[]) {
    
    //status
    int status = 0;
    
    //dispatch source
    dispatch_source_t source = 0;
    
    //pool
    @autoreleasepool {
        
        //args
        NSArray* arguments = nil;
        
        //parent
        NSString* parent = nil;
        
        //log monitor
        LogMonitor* logMonitor = nil;
        
        //log predicate
        NSPredicate* predicate = nil;
        
        //grab args
        arguments = [[NSProcessInfo processInfo] arguments];
        
        //handle '-h' or '-help'
        if( (YES == [arguments containsObject:ARGS_H]) ||
            (YES == [arguments containsObject:ARGS_HELP]) )
        {
            //print usage
            usage();
            
            //done
            goto bail;
        }
        
        //get parent
        parent = getParentBundleID();
        
        //dbg msg
        if(YES != [arguments containsObject:ARGS_JSON])
        {
            NSLog(@"Started %s (pid: %d, parent: %@) ", BUNDLE_ID, getpid(), parent);
        }
        
    
        //CHECK 0x1:
        // must be launched via Terminal
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
             if(YES != [arguments containsObject:ARGS_JSON])
             {
                 //err msg
                 NSLog(@"\n\nERROR: As %@ uses a System Extension, Apple requires it must be located in /Applications\n\n", [APP_NAME stringByDeletingPathExtension]);
             }
             //json error msg
             else
             {
                 //err msg
                 printf("{\"ERROR\": \"%s must be located in /Applications\"}\n", [APP_NAME stringByDeletingPathExtension].UTF8String);
             }
            
             goto bail;
        }
        
        //init predicate to capture log message from extension
        predicate = [NSPredicate predicateWithFormat:@"subsystem='com.objective-see.dnsmonitor'"];
        
        //init log monitor
        logMonitor = [[LogMonitor alloc] init];
        
        //start log monitor
        // ...and (forevers) print out any messages from extension
        [logMonitor start:predicate level:Log_Level_Default eventHandler:^(OSLogEventProxy* event) {
            
            //json (lines)
            if(YES == [arguments containsObject:ARGS_JSON])
            {
                //print / flush
                printf("%s\n", event.composedMessage.UTF8String);
                fflush(stdout);
                
            }
            //print
            // ...via NSLog()
            else
            {
                //dbg msg from extension
                NSLog(@"%@", event.composedMessage);
            }
            
            //inc
            recordCount++;
            
        }];
        
        //ignore SIGINT
        // as we implement our own to unload the ext
        signal(SIGINT, SIG_IGN);
        
        //create dispatch handler for SIGINT
        source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
        
        //handle SIGINT
        // stop (deactivate extension)
        dispatch_source_set_event_handler(source, ^{
            
            //json
            if(YES == [arguments containsObject:ARGS_JSON])
            {
                //end/flush
                printf("]");
                fflush(stdout);
            }
            
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
                //err msg
                if(YES != [arguments containsObject:ARGS_JSON])
                {
                    //dbg msg
                    NSLog(@"ERROR: failed to start System/Network Extension");
                }
                //json error msg
                else
                {
                    //err msg
                    printf("{\"ERROR\": \"Failed to start System/Network Extension\"}\n");
                }
                
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

//print usage
void usage(void)
{
    //name
    NSString* name = nil;
    
    //version
    NSString* version = nil;
    
    //extract name
    name = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleName"];
    
    //extract version
    version = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleVersion"];

    //usage
    printf("\n%s (v%s) usage:\n", name.UTF8String, version.UTF8String);
    printf(" %s or %s           Display this usage info\n", ARGS_H.UTF8String, ARGS_HELP.UTF8String);
    printf(" %s                 Output is formatted as JSON\n", ARGS_JSON.UTF8String);
    printf(" %s               JSON output is 'pretty-printed'\n", ARGS_PRETTY.UTF8String);
    printf(" %s <block list>   File of domains / ip addresses to block\n", ARGS_BLOCK.UTF8String);
    
    return;
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
            if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
            {
                NSLog(@"ERROR: failed to deactivate System Extension");
            }
        }
        //happy
        else
        {
            //dbg msg
            if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
            {
                NSLog(@"deactived System Extension");
            }
            
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
