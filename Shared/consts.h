//
//  file: consts.h
//  project: DNSMonitor (shared)
//  description: #defines and what not
//
//  created by Patrick Wardle
//  copyright (c) 2022 Objective-See. All rights reserved.
//

#ifndef consts_h
#define consts_h

//app name
#define APP_NAME @"DNSMonitor.app"

//bundle ID
#define BUNDLE_ID "com.objective-see.dnsmonitor"

//main app bundle id
#define APP_ID @"com.objective-see.dnsmonitor.app"

//extension bundle ID
#define EXT_BUNDLE_ID @"com.objective-see.dnsmonitor.extension"

//product url
#define PRODUCT_URL @"https://objective-see.com/products/utilities.html#DNSMonitor"

//deactivate
#define ACTION_DEACTIVATE 0

//activate
#define ACTION_ACTIVATE 1

//args
#define ARGS_H @"-h"
#define ARGS_HELP @"-help"

#define ARGS_JSON @"-json"
#define ARGS_BLOCK @"-block"
#define ARGS_PRETTY @"-pretty"

#define ARGS_DAEMON @"-daemon"
#define ARGS_UNLOAD @"-unload"

#define ARGS_BLOCK_VIA_NX @"-nx"

#endif /* const_h */
