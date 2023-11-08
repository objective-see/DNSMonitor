//
//  Extension.m
//  DNSMonitor
//
//  Created by Patrick Wardle on 8/1/22.
//  Copyright (c) 2020 Objective-See. All rights reserved.
//

#import "consts.h"
#import "Extension.h"
#import "AppDelegate.h"

/* GLOBALS */

@implementation Extension

//submit request to toggle system extension
-(void)toggleExtension:(NSUInteger)action reply:(void (^)(BOOL))reply
{
    //request
    OSSystemExtensionRequest* request = nil;
    
    //dbg msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"toggling System Extension (action: %lu)", (unsigned long)action);
    }
    
    //save reply
    self.replyBlock = reply;
        
    //activation request
    if(ACTION_ACTIVATE == action)
    {
        //dbg msg
        if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
        {
            NSLog(@"creating 'OSSystemExtensionRequest' activation request");
        }
        
        //init request
        request = [OSSystemExtensionRequest activationRequestForExtension:EXT_BUNDLE_ID queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)];
    }
    //deactivation request
    else
    {
        //dbg msg
        if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
        {
            NSLog(@"creating 'OSSystemExtensionRequest' deactivation request");
        }
        
        //init request
        request = [OSSystemExtensionRequest deactivationRequestForExtension:EXT_BUNDLE_ID queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)];
    }
    
    //sanity check
    if(nil == request)
    {
        //err msg
        if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
        {
            NSLog(@"ERROR: failed to create request for extension");
        }
        
        //bail
        goto bail;
    }
    
    //set delegate
    request.delegate = self;
    
    //dbg msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"submitting request...");
    }
       
    //submit request
    [OSSystemExtensionManager.sharedManager submitRequest:request];
    
bail:
    
    return;
}

//start network extension
-(void)startNetworkExtension:(void (^)(BOOL))reply
{
    //provider protocol
    __block NEDNSProxyProviderProtocol* protocol =  nil;
    
    //dbg msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"starting network extension...");
    }
    
    //load prefs
    [NEDNSProxyManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
        
        //err?
        if(nil != error)
        {
            //err msg
            if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
            {
                NSLog(@"ERROR: 'loadFromPreferencesWithCompletionHandler' failed with %@", error);
            }
            
            reply(NO);
            return;
        }
        
        //dbg msg
        if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
        {
            NSLog(@"activating network extension...");
        }
        
        //set description
        NEDNSProxyManager.sharedManager.localizedDescription = @"DNS";
        
        //init protocol
        protocol = [[NEDNSProxyProviderProtocol alloc] init];
        
        //set provider
        protocol.providerBundleIdentifier = EXT_BUNDLE_ID;
        
        //set protocol
        NEDNSProxyManager.sharedManager.providerProtocol = protocol;
        
        //enable
        NEDNSProxyManager.sharedManager.enabled = YES;
            
        //save preferences
        [NEDNSProxyManager.sharedManager saveToPreferencesWithCompletionHandler:^(NSError * _Nullable error) {
            
            //err?
            if(nil != error)
            {
                //err msg
                if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
                {
                    NSLog(@"ERROR: 'saveToPreferencesWithCompletionHandler' failed with %@", error);
                }
                
                reply(NO);
                return;
            }
            
            //happy
            reply(YES);
            
        }];
    }];
     
    return;
}

#pragma mark -
#pragma mark OSSystemExtensionRequest delegate methods


//replace delegate method
// always replaces, so return 'OSSystemExtensionReplacementActionReplace'
-(OSSystemExtensionReplacementAction)request:(nonnull OSSystemExtensionRequest *)request actionForReplacingExtension:(nonnull OSSystemExtensionProperties *)existing withExtension:(nonnull OSSystemExtensionProperties *)ext
{
    //dbg msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"method '%s' invoked with %@, %@ -> %@", __PRETTY_FUNCTION__, request.identifier, existing.bundleShortVersion, ext.bundleShortVersion);
    }
    
    return OSSystemExtensionReplacementActionReplace;
}


//error delegate method
-(void)request:(nonnull OSSystemExtensionRequest *)request didFailWithError:(nonnull NSError *)error
{
    //err msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"ERROR: method '%s' invoked with %@, %@", __PRETTY_FUNCTION__, request, error);
    }
    
    //invoke reply
    self.replyBlock(NO);

    return;
}


//finish delegate method
// install request? now can activate network ext
// uninstall request? now can complete uninstall
-(void)request:(nonnull OSSystemExtensionRequest *)request didFinishWithResult:(OSSystemExtensionRequestResult)result {
    
    //happy
    BOOL completed = NO;
    
    //dbg msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"method '%s' invoked with %@, %ld", __PRETTY_FUNCTION__, request, (long)result);
    }
   
    //issue/error?
    if(OSSystemExtensionRequestCompleted != result)
    {
        //err msg
        if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
        {
            NSLog(@"ERROR: result %ld is an unexpected result for system extension request", (long)result);
        }
        
        //bail
        goto bail;
    }
    
    //happy
    completed = YES;
    
bail:
    
    //reply
    self.replyBlock(completed);
    
    return;
}

//user approval delegate
// if this isn't the first time launch, will alert user to approve
-(void)requestNeedsUserApproval:(nonnull OSSystemExtensionRequest *)request {
    
    //dbg msg
    if(YES != [NSProcessInfo.processInfo.arguments containsObject:ARGS_JSON])
    {
        NSLog(@"method '%s' invoked with %@", __PRETTY_FUNCTION__, request);
    }
    
    return;
}

@end
