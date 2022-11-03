//
//  DNSProxyProvider.h
//  DNSMonitor (Extension)
//
//  Created by Patrick Wardle on 7/26/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

@import OSLog;

#import <arpa/inet.h>
#import <sys/socket.h>
#import <NetworkExtension/NetworkExtension.h>

@interface DNSProxyProvider : NEDNSProxyProvider

//DNS cache
// mappings of IP:URL
@property(nonatomic, retain)NSCache* dnsCache;

@end

