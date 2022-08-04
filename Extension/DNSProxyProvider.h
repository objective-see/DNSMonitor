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

//dns header struct
// from: http://www.nersc.gov/~scottc/software/snort/dns_head.html
#pragma pack(push,1)
struct dnsHeader {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};
#pragma pack(pop)


NS_ASSUME_NONNULL_BEGIN

@interface DNSProxyProvider : NEDNSProxyProvider

//DNS cache
// mappings of IP:URL
@property(nonatomic, retain)NSCache* dnsCache;

@end

NS_ASSUME_NONNULL_END
