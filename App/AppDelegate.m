//
//  AppDelegate.m
//  DNSMonitor
//
//  Created by Patrick Wardle on 8/1/22.
//  Copyright (c) 2020 Objective-See. All rights reserved.
//

#import "consts.h"
#import "Extension.h"
#import "AppDelegate.h"

/* GLOBALS */


@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;

@end

@implementation AppDelegate

//center window
-(void)awakeFromNib
{
    //center
    [self.window center];
    
    return;
}

//main app interface
-(void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    //foreground
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    
    //make front/active
    [NSApp activateIgnoringOtherApps:YES];
    
    //make add/edit button first responder
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (100 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
        
        //first responder
        [self.window makeFirstResponder:[self.window.contentView viewWithTag:1]];
        
    });
    
    return;
}

//exit on window close
-(BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication {
    
    return YES;
    
}

//close app
-(IBAction)close:(id)sender {
    
    //close
    // will trigger exit
    [self.window close];
    
}

//open product documentation
-(IBAction)moreInfo:(id)sender {
    
    //open
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:PRODUCT_URL]];
    
}

@end
