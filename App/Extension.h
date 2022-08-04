//
//  Extension.h
//  DNSMonitor
//
//  Created by Patrick Wardle on 8/1/22.
//  Copyright (c) 2020 Objective-See. All rights reserved.
//

@import OSLog;
@import Foundation;
@import NetworkExtension;
@import SystemExtensions;

typedef void(^replyBlockType)(BOOL);

@interface Extension : NSObject <OSSystemExtensionRequestDelegate>

/* PROPERTIES */

//reply
@property(nonatomic, copy)replyBlockType replyBlock;

/* METHODS */

//submit request to toggle extension
-(void)toggleExtension:(NSUInteger)action reply:(replyBlockType)reply;

//start network extension
-(void)startNetworkExtension:(void (^)(BOOL))reply;

@end

