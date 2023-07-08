//
//  Process.h
//  DNSMonitor
//
//  Created by Patrick Wardle on 10/8/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

#ifndef Process_h
#define Process_h

#import <libproc.h>
#import <sys/sysctl.h>
#import <Foundation/Foundation.h>

//get process's path
NSString* getProcessPath(pid_t pid);

//get process's name
NSString* getProcessName(pid_t pid, NSString* path);

//get current working dir
NSString* getProcessCWD(pid_t pid);

//find a process by name
pid_t findProcess(NSString* processName);

//extract process' commandline args
NSMutableArray* getArgs(pid_t pid);

NSDictionary* getProcessInfo(pid_t pid);

#endif /* Process_h */
