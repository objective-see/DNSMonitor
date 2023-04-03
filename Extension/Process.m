//
//  Process.m
//  Extension
//
//  Created by Patrick Wardle on 10/8/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

#import "Process.h"

//get process's path by pid
NSString* getProcessPath(pid_t pid)
{
    //task path
    NSString* processPath = nil;
    
    //cwd
    NSString* cwd = nil;
    
    //buffer for process path
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    
    //status
    int status = -1;
    
    //'management info base' array
    int mib[3] = {0};
    
    //system's size for max args
    unsigned long systemMaxArgs = 0;
    
    //process's args
    char* taskArgs = NULL;
    
    //# of args
    int numberOfArgs = 0;
    
    //size of buffers, etc
    size_t size = 0;
    
    //reset buffer
    memset(pathBuffer, 0x0, PROC_PIDPATHINFO_MAXSIZE);
    
    //first attempt to get path via 'proc_pidpath()'
    status = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
    if(0 != status)
    {
        //init task's name
        processPath = [NSString stringWithUTF8String:pathBuffer];
    }
    //otherwise
    // try via task's args ('KERN_PROCARGS2')
    else
    {
        //init mib
        // want system's size for max args
        mib[0] = CTL_KERN;
        mib[1] = KERN_ARGMAX;
        
        //set size
        size = sizeof(systemMaxArgs);
        
        //get system's size for max args
        if(-1 == sysctl(mib, 2, &systemMaxArgs, &size, NULL, 0))
        {
            //bail
            goto bail;
        }
        
        //alloc space for args
        taskArgs = malloc(systemMaxArgs);
        if(NULL == taskArgs)
        {
            //bail
            goto bail;
        }
        
        //init mib
        // want process args
        mib[0] = CTL_KERN;
        mib[1] = KERN_PROCARGS2;
        mib[2] = pid;
        
        //set size
        size = (size_t)systemMaxArgs;
        
        //get process's args
        if(-1 == sysctl(mib, 3, taskArgs, &size, NULL, 0))
        {
            //bail
            goto bail;
        }
        
        //sanity check
        // ensure buffer is somewhat sane
        if(size <= sizeof(int))
        {
            //bail
            goto bail;
        }
        
        //extract number of args
        memcpy(&numberOfArgs, taskArgs, sizeof(numberOfArgs));
        
        //extract task's name
        // follows # of args (int) and is NULL-terminated
        processPath = [NSString stringWithUTF8String:taskArgs + sizeof(int)];
        
        //short path?
        // get cwd + to append
        if(YES == [processPath hasPrefix:@"./"])
        {
            //chop ./
            processPath = [processPath substringWithRange:NSMakeRange(2, [processPath length]-2)];
            cwd = getProcessCWD(pid);
            if(nil != cwd)
            {
                //append
                processPath = [cwd stringByAppendingPathComponent:processPath];
            }
        }
    }
    
bail:
    
    //free process args
    if(NULL != taskArgs)
    {
        //free
        free(taskArgs);
        taskArgs = NULL;
    }
    
    return processPath;
}

//get process's name
NSString* getProcessName(pid_t pid, NSString* path)
{
    //status
    int status = 0;
    
    //process name
    NSString* processName = nil;
    
    //buffer for process path
    char nameBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    
    //clear
    memset(nameBuffer, 0x0, sizeof(nameBuffer));
    
    //get name
    status = proc_name(pid, &nameBuffer, sizeof(nameBuffer));
    if(status >= 0)
    {
        //init task's name
        processName = [NSString stringWithUTF8String:nameBuffer];
    }
    
    //still nil?
    // just grab from path
    if(nil == processName)
    {
        //from path
        processName = [path lastPathComponent];
    }
    
bail:
    
    return processName;
}

//get current working dir
NSString* getProcessCWD(pid_t pid)
{
    //cwd
    NSString* directory = nil;
    
    //status
    int status = -1;
    
    //path info
    struct proc_vnodepathinfo vpi = {0,};
    
    //init
    memset(&vpi, 0x0, sizeof(vpi));
    
    //get proc's cwd, via PROC_PIDVNODEPATHINFO
    status = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi));
    if(status > 0)
    {
        //convert to string
        directory = [NSString stringWithUTF8String:vpi.pvi_cdir.vip_path];
    }
    
    return directory;
}

//find a process by name
pid_t findProcess(NSString* processName)
{
    //pid
    pid_t pid = -1;
    
    //status
    int status = -1;
    
    //# of procs
    int numberOfProcesses = 0;
    
    //array of pids
    pid_t* pids = NULL;
    
    //process path
    NSString* processPath = nil;
    
    //get # of procs
    numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if(-1 == numberOfProcesses)
    {
        //bail
        goto bail;
    }
    
    //alloc buffer for pids
    pids = calloc((unsigned long)numberOfProcesses, sizeof(pid_t));
    
    //get list of pids
    status = proc_listpids(PROC_ALL_PIDS, 0, pids, numberOfProcesses * (int)sizeof(pid_t));
    if(status < 0)
    {
        //bail
        goto bail;
    }
    
    //iterate over all pids
    // get name for each via helper function
    for(int i = 0; i < numberOfProcesses; ++i)
    {
        //skip blank pids
        if(0 == pids[i])
        {
            //skip
            continue;
        }
        
        //get path
        processPath = getProcessPath(pids[i]);
        if( (nil == processPath) ||
            (0 == processPath.length) )
        {
            //skip
            continue;
        }
        
        //no match?
        if(YES != [processPath.lastPathComponent isEqualToString:processName])
        {
            //skip
            continue;
        }
            
        //save
        pid = pids[i];
        
        //pau
        break;
        
    }//all procs
    
bail:
    
    //free buffer
    if(NULL != pids)
    {
        //free
        free(pids);
        pids = NULL;
    }
    
    return pid;
}

//extract process' commandline args
NSMutableArray* getArgs(pid_t pid)
{
    //args
    NSMutableArray* arguments = nil;

    //'management info base' array
    int mib[3] = {0};
    
    //system's size for max args
    int systemMaxArgs = 0;
    
    //process's args
    char* processArgs = NULL;
    
    //# of args
    int numberOfArgs = 0;
    
    //arg
    NSString* argument = nil;
    
    //start of (each) arg
    char* argStart = NULL;
    
    //size of buffers, etc
    size_t size = 0;
    
    //parser pointer
    char* parser = NULL;
    
    //init
    arguments = [NSMutableArray array];
    
    //init mib
    // want system's size for max args
    mib[0] = CTL_KERN;
    mib[1] = KERN_ARGMAX;
    
    //set size
    size = sizeof(systemMaxArgs);
    
    //get system's size for max args
    if(-1 == sysctl(mib, 2, &systemMaxArgs, &size, NULL, 0))
    {
        //bail
        goto bail;
    }
    
    //alloc space for args
    processArgs = malloc(systemMaxArgs);
    if(NULL == processArgs)
    {
        //bail
        goto bail;
    }
    
    //init mib
    // want process args
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROCARGS2;
    mib[2] = pid;
    
    //set size
    size = (size_t)systemMaxArgs;
    
    //get process's args
    if(-1 == sysctl(mib, 3, processArgs, &size, NULL, 0))
    {
        //bail
        goto bail;
    }
    
    //sanity check
    // ensure buffer is somewhat sane
    if(size <= sizeof(int))
    {
        //bail
        goto bail;
    }
    
    //extract number of args
    // at start of buffer
    memcpy(&numberOfArgs, processArgs, sizeof(numberOfArgs));
    
    //init pointer to start of args
    // they start right after # of args
    parser = processArgs + sizeof(numberOfArgs);
    
    //scan until end of process's NULL-terminated path
    while(parser < &processArgs[size])
    {
        //scan till NULL-terminator
        if(0x0 == *parser)
        {
            //end of exe name
            break;
        }
        
        //next char
        parser++;
    }
    
    //sanity check
    // make sure end-of-buffer wasn't reached
    if(parser == &processArgs[size])
    {
        //bail
        goto bail;
    }
    
    //skip all trailing NULLs
    // scan will end when non-NULL is found
    while(parser < &processArgs[size])
    {
        //scan till NULL-terminator
        if(0x0 != *parser)
        {
            //ok, got to argv[0]
            break;
        }
        
        //next char
        parser++;
    }
    
    //sanity check
    // (again), make sure end-of-buffer wasn't reached
    if(parser == &processArgs[size])
    {
        //bail
        goto bail;
    }
    
    //parser should now point to argv[0], process name
    // init arg start
    argStart = parser;
    
    //keep scanning until all args are found
    // each is NULL-terminated
    while(parser < &processArgs[size])
    {
        //each arg is NULL-terminated
        // so scan till NULL, then save into array
        if(*parser == '\0')
        {
            //save arg
            if(NULL != argStart)
            {
                //try convert
                // ignore (if not UTF8, etc...)
                argument = [NSString stringWithUTF8String:argStart];
                if(nil != argument)
                {
                    //save
                    [arguments addObject:argument];
                }
            }
            
            //init string pointer to (possibly) next arg
            argStart = ++parser;
            
            //bail if we've hit arg cnt
            if(arguments.count == numberOfArgs)
            {
                //bail
                break;
            }
        }
        
        //next char
        parser++;
    }
    
bail:
    
    //free process args
    if(NULL != processArgs)
    {
        //free
        free(processArgs);
        
        //unset
        processArgs = NULL;
    }
    
    return arguments;
}
