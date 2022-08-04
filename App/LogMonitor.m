//
//  logMonitor.m
//  logAPI
//
//  Created by Patrick Wardle on 4/30/21.
//  Copyright © 2021 Objective-See. All rights reserved.
//

@import OSLog;

#import "LogMonitor.h"

@implementation LogMonitor

//start logging
// pass in predicate to match, log level, and callback for event handler
-(BOOL)start:(NSPredicate*)predicate level:(NSUInteger)level eventHandler:(void(^)(OSLogEventProxy*))eventHandler
{
    //flag
    BOOL started = NO;
    
    //live stream class
    Class LiveStream = nil;
    
    //load 'LoggingSupport.framework'
    [[NSBundle bundleWithPath:LOGGING_SUPPORT] load];

    //get 'OSLogEventLiveStream' class
    if(nil == (LiveStream = NSClassFromString(@"OSLogEventLiveStream")))
    {
        //bail
        goto bail;
    }

    //init live stream
    self.liveStream = [[LiveStream alloc] init];
    if(nil == self.liveStream)
    {
        //bail
        goto bail;
    }

    //sanity check
    // obj responds to `setFilterPredicate:`?
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"setFilterPredicate:")])
    {
        //bail
        goto bail;
    }

    //set predicate
    if(nil != predicate)
    {
        [self.liveStream setFilterPredicate:predicate];
    }
    

    //sanity check
    // obj responds to `setInvalidationHandler:`?
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"setInvalidationHandler:")])
    {
        //bail
        goto bail;
    }

    //set invalidation handler
    // note: need to have somethigng set as this get called (indirectly) when
    //       the 'invalidate' method is called ... but don't need to do anything
    [self.liveStream setInvalidationHandler:^void (int reason, id streamPosition) {
        //NSLog(@"invalidation handler called with %d!", reason);
        ;
    }];

    //sanity check
    // obj responds to `setDroppedEventHandler:`?
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"setDroppedEventHandler:")])
    {
        //bail
        goto bail;
    }

    //set dropped msg handler
    // note: need to have somethigng set as this get called (indirectly)
    [self.liveStream setDroppedEventHandler:^void (id droppedMessage)
    {
        //NSLog(@"invalidation handler called with %d!", reason);
        ;
    }];

    //sanity check
    // obj responds to `setEventHandler:`?
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"setEventHandler:")])
    {
        //bail
        goto bail;
    }

    //set event handler
    [self.liveStream setEventHandler:eventHandler];

    //sanity check
    // obj responds to `activate:`?
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"activate")])
    {
        //bail
        goto bail;
    }
    
    //
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"setFlags:")])
    {
        //bail
        goto bail;
    }

    //set debug & info flags
    [self.liveStream setFlags:level];
    
    //activate
    [self.liveStream activate];

    //happy
    started = YES;

bail:

    return started;
}

//stop stream
// invalidates live stream
-(void)stop
{
    //sanity check
    // obj responds to `invalidate`?
    if(YES != [self.liveStream respondsToSelector:NSSelectorFromString(@"invalidate")])
    {
        //bail
        goto bail;
    }

    //not nil?
    // invalidate
    if(nil != self.liveStream)
    {
        //invalidate
        [self.liveStream invalidate];
    }

bail:

    return;
}

@end
