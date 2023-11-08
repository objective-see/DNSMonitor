//
//  DNSProxyProvider.m
//  DNSMonitor (Extension)
//
//  Created by Patrick Wardle on 7/26/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

#import <nameser.h>
#import <libproc.h>
#import <dns_util.h>
#import <bsm/libbsm.h>

#import "Consts.h"
#import "Process.h"
#import "DNSProxyProvider.h"

#define DNS_FLAGS_QR_MASK  0x8000
#define DNS_FLAGS_QR_QUERY 0x0000

#define DNS_FLAGS_OPCODE_MASK    0x7800
#define DNS_FLAGS_RCODE_MASK 0x000f

#define DNS_FLAGS_AA 0x0400
#define DNS_FLAGS_TC 0x0200
#define DNS_FLAGS_RD 0x0100
#define DNS_FLAGS_RA 0x0080

#define INET_NTOP_AF_INET_OFFSET 4
#define INET_NTOP_AF_INET6_OFFSET 8

#define PROCESS_ID @"pid"
#define PROCESS_NAME @"name"
#define PROCESS_PATH @"path"
#define PROCESS_SIGNING_ID @"signing ID"

#define MAX_ENTRIES 1024

/* GLOBALS */

//log handle
extern os_log_t logHandle;

//(app's) arguments
extern NSMutableArray* appArgs;

//DNS cache
NSMutableArray* dnsCache;

//invoked via SIGUSR1
// dump the DNS cache to the system log
void dumpDNSCache(int signal) {
    
    //question
    NSString* question = nil;
    
    //for json
    NSData* json = nil;
    
    //json output?
    if(YES == [appArgs containsObject:ARGS_JSON])
    {
        //serialize to JSON
        // wrap since we are serializing JSON
        @try
        {
            //serialize
            json = [NSJSONSerialization dataWithJSONObject:dnsCache options:0 error:nil];
        }
        //ignore exceptions
        @catch(NSException *exception)
        {
            //bail
            goto bail;
        }
        
        //print (json)
        os_log(logHandle, "%{public}@", [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]);
        
    }
    //just print as is
    else
    {
        //dbg msg
        os_log(logHandle, "Dumping DNS Cache:");
        
        //print all
        for(NSDictionary* entry in dnsCache)
        {
            //get question
            // always first/only key
            question = entry.allKeys.firstObject;
            
            //print
            os_log(logHandle, "%{public}@:%{public}@", question, entry[question]);
        }
    }
    
bail:
    
    return;
}

@interface NSMutableArray (DNSCache)

-(void)cache:(dns_reply_t*)packet;

@end

@implementation NSMutableArray (DNSCache)

//save to cache
// note: dump via # kill -SIGUSR1 <pid of com.objective-see.dnsmonitor.extension>
-(void)cache:(dns_reply_t*)packet
{
    //header
    dns_header_t* header = nil;
    
    //init header
    header = packet->header;
    
    //questions
    NSMutableArray* questions = nil;
    
    //answers
    NSMutableArray* answers = nil;

    //init
    questions = [NSMutableArray array];
    
    //init
    answers = [NSMutableArray array];

    //add each question
    for(uint16_t i = 0; i < header->qdcount; i++)
    {
        //question
        NSString* question = nil;
        
        //check question
        if(NULL != packet->question[i]->name)
        {
            //init question
            if(nil != (question = [NSString stringWithUTF8String:packet->question[i]->name]))
            {
                //add
                [questions addObject:question];
            }
        }
    }
    
    //add each answer
    for(uint16_t i = 0; i < header->ancount; i++)
    {
        //value
        NSString* answer = nil;
        
        //ipv6
        struct sockaddr_in6 s6 = {0};
        
        //buffer
        char hostBuffer[INET6_ADDRSTRLEN+1] = {0};
        
        //handle specific types
        switch(packet->answer[i]->dnstype)
        {
            //host (IPv4)
            case ns_t_a:
                
                //check / add
                if(nil != (answer = [NSString stringWithUTF8String:inet_ntoa(packet->answer[i]->data.A->addr)]))
                {
                   //add
                   [answers addObject:answer];
                }
                
                break;
                
            //host (IPv6)
            case ns_t_aaaa:
                
                //clear
                memset(&s6, 0, sizeof(struct sockaddr_in6));
                
                //init
                s6.sin6_len = sizeof(struct sockaddr_in6);
                s6.sin6_family = AF_INET6;
                s6.sin6_addr = packet->answer[i]->data.AAAA->addr;
                
                //host
                if(nil != (answer = [NSString stringWithUTF8String:inet_ntop(AF_INET6, (char *)(&s6) + INET_NTOP_AF_INET6_OFFSET, hostBuffer, INET6_ADDRSTRLEN)]))
                {
                   //add
                   [answers addObject:answer];
                }
        }
    }

    //sync
    @synchronized (dnsCache)
    {
        //need to prune?
        if(dnsCache.count >= MAX_ENTRIES)
        {
            //prune
            [dnsCache removeObjectsInRange:NSMakeRange(0, MAX_ENTRIES/2)];
        }
        
        //add to cache
        // if there was answer
        for(NSString* question in questions)
        {
            //add
            if(0 != answers.count)
            {
                //add
                [dnsCache addObject:@{question:answers}];
            }
        }
        
    } //sync
        
    return;
}

@end

@implementation DNSProxyProvider

//start proxy
-(void)startProxyWithOptions:(NSDictionary<NSString *,id> *)options
            completionHandler:(void (^)(NSError *error))completionHandler
{
    //init DNS 'cache'
    dnsCache = [NSMutableArray array];
            
    //dbg msg
    if(YES != [appArgs containsObject:ARGS_JSON])
    {
        os_log(logHandle, "method '%s' invoked", __PRETTY_FUNCTION__);
    }
    
    //block list
    if(YES == [appArgs containsObject:ARGS_BLOCK])
    {
        //load
        [self loadBlockList];
    }
    //no block list
    else
    {
        //dbg msg
        if(YES != [appArgs containsObject:ARGS_JSON])
        {
            os_log(logHandle, "no block list specified, all traffic will be allowed");
        }
    }
    
    //setup signal handler
    // on signal will dump dns cache
    signal(SIGUSR1, dumpDNSCache);
    
    //call completion handler
    completionHandler(nil);
    
    return;
    
}

//load block list
-(void)loadBlockList
{
    //index
    NSUInteger index = NSNotFound;
    
    //file path
    NSString* path = nil;
    
    //data
    NSData* data = nil;

    //error
    NSError* error = nil;
    
    //array
    NSArray* array = nil;
    
    //get index
    index = [appArgs indexOfObject:ARGS_BLOCK];
    
    //file should be next
    index++;
    
    //sanity check
    if(index >= appArgs.count)
    {
        //bail
        goto bail;
    }
    
    //extract file path
    path = [appArgs objectAtIndex:index];
    
    //dbg msg
    if(YES != [appArgs containsObject:ARGS_JSON])
    {
        os_log(logHandle, "using block list: %{public}@", path);
    }
    
    //sanity check
    if(YES != [NSFileManager.defaultManager fileExistsAtPath:path])
    {
        //err msg
        if(YES != [appArgs containsObject:ARGS_JSON])
        {
            os_log_error(logHandle, "ERROR: failed to find specified block list: %{public}@", path);
        }
        
        //bail
        goto bail;
    }
    
    //try load data
    data = [NSData dataWithContentsOfFile:path];
    if(nil == data)
    {
        //err msg
        if(YES != [appArgs containsObject:ARGS_JSON])
        {
            os_log_error(logHandle, "ERROR: failed to load block list: %{public}@", path);
        }
        
        //bail
        goto bail;
    }
   
    //convert (JSON) data to array
    array = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];
    if( (nil == array) ||
        (nil != error) )
    {
        //err msg
        if(YES != [appArgs containsObject:ARGS_JSON])
        {
            os_log_error(logHandle, "ERROR: failed to unserialized block list: %{public}@", path);
        }
        
        //bail
        goto bail;
    }
    
    //covert to set
    self.blockList = [NSSet setWithArray:array];
    
bail:
    
    return;
}

//stop proxy
-(void)stopProxyWithReason:(NEProviderStopReason)reason
          completionHandler:(void (^)(void))completionHandler
{
    //dbg msg
    if(YES != [appArgs containsObject:ARGS_JSON])
    {
        os_log(logHandle, "method '%s' invoked", __PRETTY_FUNCTION__);
    }
    
    //call completion handler
    completionHandler();
    
    return;
}

//handle new flow
-(BOOL)handleNewFlow:(NEAppProxyFlow *)flow
{
    //flag
    BOOL handled = NO;

    //is a UDP flow?
    if(YES == [flow isKindOfClass:[NEAppProxyUDPFlow class]])
    {
        //open flow
        [(NEAppProxyUDPFlow*)flow openWithLocalEndpoint:(NWHostEndpoint*)((NEAppProxyUDPFlow*)flow).localEndpoint completionHandler:^(NSError *error)
        {
                
            if(error == nil)
            {
                //read from flow
                // and send to remote endpoint
                [self flowOutUDP:(NEAppProxyUDPFlow*)flow];
            }
            
        }];
        
        //set flag
        handled = YES;
    }
    
    //is a TCP flow?
    else if(YES == [flow isKindOfClass:[NEAppProxyTCPFlow class]])
    {
        //tcp
        NEAppProxyTCPFlow* tcpFlow = NULL;
        
        //type cast
        tcpFlow = (NEAppProxyTCPFlow*)flow;
        
        //(remote) connection
        nw_connection_t remoteConnection = nil;
        
        //(remote) endpoint
        nw_endpoint_t remoteEndpoint = nil;
        
        //create an (nw_)endpoint
        remoteEndpoint = nw_endpoint_create_host(((NWHostEndpoint*)tcpFlow.remoteEndpoint).hostname.UTF8String, ((NWHostEndpoint*)tcpFlow.remoteEndpoint).port.UTF8String);
        if(NULL == remoteEndpoint)
        {
            //err msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log_error(logHandle, "ERROR: 'nw_endpoint_create_host' returned NULL");
            }
            
            //close
            [flow closeWriteWithError:nil];
            
            //set flag
            handled = NO;
            
            //bail
            goto bail;
        }
        
        //create connection
        remoteConnection = nw_connection_create(remoteEndpoint, nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
        if(NULL == remoteConnection)
        {
            //err msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log_error(logHandle, "ERROR: 'nw_connection_create' returned NULL");
            }
            
            //close
            [flow closeWriteWithError:nil];
            
            //set flag
            handled = NO;
            
            //bail
            goto bail;
        }
        
        //set queue
        nw_connection_set_queue(remoteConnection, dispatch_get_main_queue());
        
        //set handler
        // will be invoked with various states
        nw_connection_set_state_changed_handler(remoteConnection, ^(nw_connection_state_t state, nw_error_t error)
        {
            //error?
            if(NULL != error)
            {
                //err msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log_error(logHandle, "ERROR: 'nw_connection_set_state_changed_handler' failed with %d", nw_error_get_error_code(error));
                }
                
                //close
                [flow closeWriteWithError:nil];
                
                return;
            }
            
            //handle state
            // mostly only care about "ready"
            switch (state) {
                    
                //ready?
                // send datagram & read (response)
                case nw_connection_state_ready: {
                    
                    //local host
                    NSString* localHost = nil;
                    
                    //local port
                    NSString* localPort = nil;
                    
                    //(local) endpoint
                    nw_endpoint_t localEndpoint = nil;
                    
                    //local host endpoint
                    NWHostEndpoint* localHostEndpoint = nil;
                    
                    //grab local endpoint
                    localEndpoint = nw_path_copy_effective_local_endpoint(nw_connection_copy_current_path(remoteConnection));
                    
                    //extract local host/port
                    localHost = [NSString stringWithUTF8String:nw_endpoint_get_hostname(localEndpoint)];
                    localPort = [NSString stringWithFormat:@"%d", nw_endpoint_get_port(localEndpoint)];
                    
                    //create local host endpoint
                    localHostEndpoint = [NWHostEndpoint endpointWithHostname:localHost port:localPort];
                    
                    //open flow
                    [flow openWithLocalEndpoint:localHostEndpoint completionHandler:^(NSError *error)
                    {
                        //error?
                        if(nil != error)
                        {
                            //err msg
                            if(YES != [appArgs containsObject:ARGS_JSON])
                            {
                                os_log_error(logHandle, "ERROR: 'openWithLocalEndpoint' failed with %{public}@", error);
                            }
                            
                            //close
                            [flow closeWriteWithError:nil];
            
                            return;
                        }
                        
                        //no error
                        // read and and send to remote endpoint
                        [self flowOutTCP:(NEAppProxyTCPFlow*)flow connection:remoteConnection];
                        [self flowInTCP:(NEAppProxyTCPFlow*)flow connection:remoteConnection];
                        
                    }];
                    
                    break;
                }
                    
                //waiting
                case nw_connection_state_waiting:
                    break;
                    
                //cancelled
                case nw_connection_state_cancelled:
                    nw_connection_cancel(remoteConnection);
                    break;
                    
                //failed
                case nw_connection_state_failed:
                    nw_connection_cancel(remoteConnection);
                    break;
                    
                default:
                    break;
            }
        });
        
        //start
        // will trigger state changed
        nw_connection_start(remoteConnection);
     
        //set flag
        handled = YES;
    }
    
    //flow is neither TCP nor UDP
    else
    {
        //err msg
        if(YES != [appArgs containsObject:ARGS_JSON])
        {
            //err msg
            os_log_error(logHandle, "ERROR: dropping unsupported flow type (%{public}@)", flow.className);
        }
        //json error msg
        else
        {
            //err msg
            printf("{\"ERROR\": \"dropping unsupported flow type (%s)\"}\n", flow.className.UTF8String);
        }
        
        //set flag
        handled = NO;
    }
    
bail:
        
    return handled;
}

//read from (remote) endpoint, then write to flow
-(void)flowInUDP:(NEAppProxyUDPFlow*)flow connection:(nw_connection_t)connection endpoint:(NWHostEndpoint*)endpoint
{
    //read from (remote) connection
    nw_connection_receive(connection, 1, UINT32_MAX,
        ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        
                //packet
                NSData* packet = nil;
        
                //parsed packet
                dns_reply_t* parsedPacket = NULL;
        
                //flag
                BOOL block = NO;
        
                //error?
                if(nil != receive_error)
                {
                    //err msg
                    if(YES != [appArgs containsObject:ARGS_JSON])
                    {
                        os_log_error(logHandle, "ERROR: nw_connection_receive failed with %d", nw_error_get_error_code(receive_error));
                    }
                    
                    return;
                }
        
                //extract packet
                packet = (NSData*)content;
                
                //parse & print
                parsedPacket = dns_parse_packet(packet.bytes, (uint32_t)packet.length);
                if(NULL != parsedPacket)
                {
                    //print
                    [self printPacket:parsedPacket flow:flow];
                    
                    //write to cache
                    [dnsCache cache:parsedPacket];
                    
                    //block list specified?
                    if(nil != self.blockList)
                    {
                        //should block?
                        block = [self shouldBlock:parsedPacket];
                    }
                    
                    //free
                    dns_free_reply(parsedPacket);
                }
        
                //block?
                if(YES == block)
                {
                    //dbg msg
                    if(YES != [appArgs containsObject:ARGS_JSON])
                    {
                        os_log(logHandle, "blocking request (not writing to local flow)");
                    }
                    
                    //close
                    [flow closeWriteWithError:nil];
                    return;
                }
        
                //write to flow
                [flow writeDatagrams:@[(NSData*)content] sentByEndpoints:@[endpoint] completionHandler:^(NSError *error)
                {
                    //error?
                    if(nil != error)
                    {
                        //close
                        [flow closeWriteWithError:nil];
                        
                        //err msg
                        if(YES != [appArgs containsObject:ARGS_JSON])
                        {
                            os_log_error(logHandle, "writeDatagrams ERROR: %{public}@", error);
                        }
        
                        return;
                    }
                    
                }];
        
                //complete
                if(YES == is_complete)
                {
                    //close
                    nw_connection_set_state_changed_handler(connection, NULL);
                    nw_connection_cancel(connection);
                }
        
            });
        
    return;
    
}

//read from flow, then write to (remote) endpoint
-(void)flowOutUDP:(NEAppProxyUDPFlow*)flow {

    //read from flow
    [flow readDatagramsWithCompletionHandler:^(NSArray* datagrams, NSArray* endpoints, NSError *error){
        
        //flag
        BOOL block = NO;
        
        //error?
        if(nil != error)
        {
            //err msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log_error(logHandle, "ERROR: 'readDatagramsWithCompletionHandler' failed with %{public}@", error);
            }
            
            //close
            [flow closeReadWithError:error];
            
            return;
        }
        
        //ended?
        // close up
        if(0 == datagrams.count)
        {
            //close
            [flow closeReadWithError:error];
            return;
        }
        
        //create connection to each (remote) endpoint
        // once connection is ready, read off each (remote) endpoint
        for(int i=0; i<datagrams.count; i++)
        {
            //packet
            NSData* packet = nil;
            
            //parsed packet
            dns_reply_t* parsedPacket = NULL;
            
            //endpoint, connection, etc
            nw_endpoint_t endpoint = nil;
            nw_connection_t connection = nil;
            
            //extract packet
            packet = datagrams[i];
            
            //parse & print
            parsedPacket = dns_parse_packet(packet.bytes, (uint32_t)packet.length);
            if(NULL != parsedPacket)
            {
                //print
                [self printPacket:parsedPacket flow:flow];
                
                //block list specified?
                if(nil != self.blockList)
                {
                    //should block?
                    block = [self shouldBlock:parsedPacket];
                }
                
                //free
                dns_free_reply(parsedPacket);
            }
            
            //block?
            if(YES == block)
            {
                //dbg msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log(logHandle, "blocking request (not sending to remote endpoint)");
                }
                
                //close
                [flow closeWriteWithError:nil];
                
                return;
            }
            
            //create an (nw_)endpoint
            endpoint = nw_endpoint_create_host(((NWHostEndpoint*)endpoints[i]).hostname.UTF8String, ((NWHostEndpoint*)endpoints[i]).port.UTF8String);
            if(NULL == endpoint)
            {
                //err msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log_error(logHandle, "ERROR: 'nw_endpoint_create_host' returned NULL");
                }
                
                //close
                [flow closeWriteWithError:nil];
                
                return;
            }
            
            //create connection
            connection = nw_connection_create(endpoint, nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
            if(NULL == connection)
            {
                //err msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log_error(logHandle, "ERROR: 'nw_connection_create' returned NULL");
                }
                
                //close
                [flow closeWriteWithError:nil];
                
                return;
            }
            
            //set queue
            nw_connection_set_queue(connection, dispatch_get_main_queue());
            
            //set handler
            // will be invoked with various states
            nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error)
            {
                //error?
                if(NULL != error)
                {
                    //err msg
                    if(YES != [appArgs containsObject:ARGS_JSON])
                    {
                        os_log_error(logHandle, "ERROR: 'nw_connection_set_state_changed_handler' failed with %d", nw_error_get_error_code(error));
                    }
                    
                    //close
                    [flow closeWriteWithError:nil];
                    
                    return;
                }
                
                //handle state
                // mostly only care about "ready"
                switch (state) {
                        
                    //ready?
                    // send datagram & read (response)
                    case nw_connection_state_ready: {
                        
                        //data
                        dispatch_data_t data = NULL;
                        
                        //create dispatch data
                        data = dispatch_data_create(((NSData*)datagrams[i]).bytes, ((NSData*)datagrams[i]).length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                        
                        //send datagram
                        nw_connection_send(connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error)
                        {
                            //error
                            if(NULL != error)
                            {
                                //err msg
                                if(YES != [appArgs containsObject:ARGS_JSON])
                                {
                                    os_log_error(logHandle, "ERROR: 'nw_connection_send' failed with %d", nw_error_get_error_code(error));
                                }
                                
                                //close
                                [flow closeWriteWithError:nil];
                                
                                return;
                            }
                            
                        });
                        
                        //now read from remote connection and write to (local) flow
                        [self flowInUDP:flow connection:connection endpoint:endpoints[i]];
                        
                        break;
                    }
                        
                    //waiting
                    case nw_connection_state_waiting:
                        break;
                        
                    //cancelled
                    case nw_connection_state_cancelled:
                        nw_connection_cancel(connection);
                        break;
                        
                    //failed
                    case nw_connection_state_failed:
                        nw_connection_cancel(connection);
                        break;
                        
                    default:
                        break;
                }
            });
            
            //start
            // will trigger state changed
            nw_connection_start(connection);
        }
        
    }];

    return;
}

//read from (remote) endpoint, then write to flow
-(void)flowInTCP:(NEAppProxyTCPFlow*)flow connection:(nw_connection_t)connection
{
    //read from (remote) connection
    nw_connection_receive(connection, 1, UINT32_MAX,
        ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error)
    {
            //length
            uint16_t length = 0;
        
            //packet
            const void* packet = NULL;
        
            //parsed packet
            dns_reply_t* parsedPacket = NULL;
        
            //flag
            BOOL block = NO;
        
            //error?
            if(nil != receive_error)
            {
                //err msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log_error(logHandle, "ERROR: nw_connection_receive failed with %d", nw_error_get_error_code(receive_error));
                }
                
                return;
            }
        
            //no length?
            // just ingore...
            if(((NSData*)content).length < 2)
            {
                return;
            }
        
            //extact bytes
            memcpy(&length, ((NSData*)content).bytes, sizeof(uint16_t));
        
            //convert
            length = ntohs(length);
        
            //not whole packet?
            // for now, just ignore
            if(((NSData*)content).length < sizeof(uint16_t) + length)
            {
                //err msg
                //err msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log_error(logHandle, "ERROR: reported length %d, greater than packet length %lu", length, (unsigned long)((NSData*)content).length);
                }
                return;
            }
        
            //packet data
            // comes right after header
            packet = ((NSData*)content).bytes+sizeof(uint16_t);
        
            //parse & print
            parsedPacket = dns_parse_packet(packet, length);
            if(NULL != parsedPacket)
            {
                //print
                [self printPacket:parsedPacket flow:flow];
                
                //block list specified?
                if(nil != self.blockList)
                {
                    //should block?
                    block = [self shouldBlock:parsedPacket];
                }
                
                //free
                dns_free_reply(parsedPacket);
            }
        
            //block?
            if(YES == block)
            {
                //dbg msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log(logHandle, "blocking request (not writing to local flow)");
                }
                
                //close
                [flow closeWriteWithError:nil];
                
                //close
                nw_connection_set_state_changed_handler(connection, NULL);
                nw_connection_cancel(connection);
                
                return;
            }
        
            //got data to write?
            if(0 != ((NSData*)content).length)
            {
                //write to flow
                [flow writeData:(NSData*)content withCompletionHandler:^(NSError * _Nullable error)
                {
                    //error?
                    if(nil != error)
                    {
                        //err msg
                        if(YES != [appArgs containsObject:ARGS_JSON])
                        {
                            os_log_error(logHandle, "writeDatagrams ERROR: %{public}@", error);
                        }
                        
                        //close
                        [flow closeWriteWithError:nil];
                        
                        return;
                    }
                    
                    //no error
                    // setup another read
                    [self flowInTCP:flow connection:connection];
                    
                }];
            }
    
            //complete?
            if(YES == is_complete)
            {
                //close
                nw_connection_set_state_changed_handler(connection, NULL);
                nw_connection_cancel(connection);
                
                return;
            }
        
            });
        
    return;
    
}

//read from flow, then write to (remote) endpoint
-(void)flowOutTCP:(NEAppProxyTCPFlow*)flow connection:(nw_connection_t)remoteConnection
{
    //read from local flow
    [flow readDataWithCompletionHandler:^(NSData * _Nullable data, NSError * _Nullable error)
    {
        //length
        uint16_t length = 0;
        
        //packet
        const void* packet = NULL;
        
        //parsed packet
        dns_reply_t* parsedPacket = NULL;
        
        //flag
        BOOL block = NO;
        
        //error?
        if(nil != error)
        {
            //err msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log_error(logHandle, "ERROR: 'readDataWithCompletionHandler' failed with %{public}@", error);
            }
            
            //close
            [flow closeReadWithError:error];
            
            return;
        }
        
        //ended?
        // close up
        if(0 == data.length)
        {
            //close
            [flow closeReadWithError:error];
            return;
        }
        
        //no length?
        // just ingore...
        if(data.length < 2)
        {
            return;
        }
        
        //extact bytes
        memcpy(&length, data.bytes, sizeof(uint16_t));
        
        //convert
        length = ntohs(length);
        
        //not whole packet?
        // for now, just ignore
        if(data.length < sizeof(uint16_t) + length)
        {
            //err msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log_error(logHandle, "ERROR: reported length %d, greater than packet length %lu", length, (unsigned long)data.length);
            }
            return;
        }
        
        //packet data
        // comes right after header
        packet = data.bytes+sizeof(uint16_t);
        
        //parse & print
        parsedPacket = dns_parse_packet(packet, length);
        if(NULL != parsedPacket)
        {
            //print
            [self printPacket:parsedPacket flow:flow];
            
            //block list specified?
            if(nil != self.blockList)
            {
                //should block?
                block = [self shouldBlock:parsedPacket];
            }
            
            //free
            dns_free_reply(parsedPacket);
        }
        
        //block?
        if(YES == block)
        {
            //dbg msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log(logHandle, "blocking request (not sending to remote endpoint)");
            }
            
            //close
            [flow closeWriteWithError:nil];
            
            //close
            nw_connection_set_state_changed_handler(remoteConnection, NULL);
            nw_connection_cancel(remoteConnection);
            
            return;
        }
        
        //data
        dispatch_data_t dispatchData = NULL;
        
        //create dispatch data
        dispatchData = dispatch_data_create(data.bytes, data.length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        
        //send to remote endpoint
        nw_connection_send(remoteConnection, dispatchData, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error)
        {
            //error
            if(NULL != error)
            {
                //err msg
                if(YES != [appArgs containsObject:ARGS_JSON])
                {
                    os_log_error(logHandle, "ERROR: 'nw_connection_send' failed with %d", nw_error_get_error_code(error));
                }
                
                //close
                [flow closeWriteWithError:nil];
                
                //close
                nw_connection_set_state_changed_handler(remoteConnection, NULL);
                nw_connection_cancel(remoteConnection);
                
                return;
            }
            
            //no error
            // setup another read from flow / send
            [self flowOutTCP:flow connection:remoteConnection];
            
        });
    
    }];

    return;
}

//check if a request/response should be blocked
-(BOOL)shouldBlock:(dns_reply_t*)packet
{
    //flag
    BOOL block = NO;
    
    //header
    dns_header_t* header = nil;
    
    //init header
    header = packet->header;
    
    //QR
    // query
    if(DNS_FLAGS_QR_QUERY == (header->flags & DNS_FLAGS_QR_MASK))
    {
        //check each question
        for(uint16_t i = 0; i < header->qdcount; i++)
        {
            //question
            NSString* question = nil;
            
            //check question
            if(NULL != packet->question[i]->name)
            {
                //init question
                question = [NSString stringWithUTF8String:packet->question[i]->name];
                if( (0 != question.length) &&
                    (YES == [self.blockList containsObject:question]) )
                {
                    //set flag
                    block = YES;
                    
                    //dbg msg
                    if(YES != [appArgs containsObject:ARGS_JSON])
                    {
                        os_log(logHandle, "will block request, question: %{public}@", question);
                    }
                    
                    //done
                    goto bail;
                }
            }
        }
        
    } //query
    
    //QR
    // reply
    else
    {
        //check each answer
        for(uint16_t i = 0; i < header->ancount; i++)
        {
            //value
            NSString* answer = nil;
            
            //ipv6
            struct sockaddr_in6 s6 = {0};
            
            //buffer
            char hostBuffer[INET6_ADDRSTRLEN+1] = {0};
            
            //handle specific types
            switch(packet->answer[i]->dnstype)
            {
                //host (IPv4)
                case ns_t_a:
                    
                    //check / add
                    if(nil != (answer = [NSString stringWithUTF8String:inet_ntoa(packet->answer[i]->data.A->addr)]))
                    {
                        if( (0 != answer.length) &&
                            (YES == [self.blockList containsObject:answer]) )
                        {
                            //set flag
                            block = YES;
                            
                            //dbg msg
                            if(YES != [appArgs containsObject:ARGS_JSON])
                            {
                                os_log(logHandle, "will block reply, answer: %{public}@", answer);
                            }
                            
                            //done
                            goto bail;
                        }
                    }
                    
                    break;
                    
                //host (IPv6)
                case ns_t_aaaa:
                    
                    //clear
                    memset(&s6, 0, sizeof(struct sockaddr_in6));
                    
                    //init
                    s6.sin6_len = sizeof(struct sockaddr_in6);
                    s6.sin6_family = AF_INET6;
                    s6.sin6_addr = packet->answer[i]->data.AAAA->addr;
                    
                    //host
                    if(nil != (answer = [NSString stringWithUTF8String:inet_ntop(AF_INET6, (char *)(&s6) + INET_NTOP_AF_INET6_OFFSET, hostBuffer, INET6_ADDRSTRLEN)]))
                    {
                        if( (0 != answer.length) &&
                            (YES == [self.blockList containsObject:answer]) )
                        {
                            //set flag
                            block = YES;
                            
                            //done
                            goto bail;
                        }
                    }
            }
        }
        
    } //reply
    
bail:
    
    return block;
}

//get process info
-(NSMutableDictionary*)getProcessInfo:(NEAppProxyFlow*)flow
{
    //status
    OSStatus status = !errSecSuccess;
    
    //code ref
    SecCodeRef code = NULL;
    
    //path
    NSString* path = nil;
    
    //name
    NSString* name = nil;
    
    //path
    CFURLRef pathURL = nil;
    
    //process info
    NSMutableDictionary* processInfo = nil;

    //audit token
    audit_token_t* auditToken = NULL;
    
    //pid
    pid_t pid = 0;
    
    //init
    processInfo = [NSMutableDictionary dictionary];
    
    //save signing id
    if(0 != flow.metaData.sourceAppSigningIdentifier.length)
    {
        //save
        processInfo[PROCESS_SIGNING_ID] = flow.metaData.sourceAppSigningIdentifier;
    }
    
    //extract audit token
    auditToken = (audit_token_t *)flow.metaData.sourceAppAuditToken.bytes;
    
    //get pid
    pid = audit_token_to_pid(*auditToken);
    
    //save pid
    processInfo[PROCESS_ID] = [NSNumber numberWithUnsignedInt:pid];
    
    //obtain code ref from audit token
    status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef _Nullable)(@{(__bridge NSString *)kSecGuestAttributeAudit:flow.metaData.sourceAppAuditToken}), kSecCSDefaultFlags, &code);
    if(errSecSuccess == status)
    {
        //copy path
        status = SecCodeCopyPath(code, kSecCSDefaultFlags, &pathURL);
        if(errSecSuccess != status)
        {
            //err msg
            if(YES != [appArgs containsObject:ARGS_JSON])
            {
                os_log_error(logHandle, "ERROR: 'SecCodeCopyPath' failed with %#x", status);
            }
                    
            //bail
            goto bail;
        }
        
        //save path
        processInfo[PROCESS_PATH] = [((__bridge NSURL*)pathURL).path copy];
    }
    //no such file?
    // try other method(s)
    else if(kPOSIXErrorENOENT == status)
    {
        //get path
        path = getProcessPath(pid);
        if(nil != path)
        {
            //save path
            processInfo[PROCESS_PATH] = path;
        }
    }
    //other error
    else
    {
        //err msg
        if(YES != [appArgs containsObject:ARGS_JSON])
        {
            os_log_error(logHandle, "ERROR: 'SecCodeCopyGuestWithAttributes' failed with %#x", status);
        }
    }
    
    //get name
    name = getProcessName(pid, path);
    if(0 != name.length)
    {
        //save
        processInfo[PROCESS_NAME] = name;
    }
    
bail:
    
    //free path url
    if(NULL != pathURL)
    {
        //free
        CFRelease(pathURL);
        pathURL = NULL;
    }
    
    //free code ref
    if(NULL != code)
    {
        //free
        CFRelease(code);
        code = NULL;
    }
    
    return processInfo;
}

//print a packet
// app's args control verbosity/format
-(void)printPacket:(dns_reply_t*)packet flow:(NEAppProxyFlow*)flow
{
    //file pointer
    FILE *fp = NULL;
    
    //bytes
    char *bytes = NULL;
    
    //size
    size_t length = 0;
    
    //process info
    NSMutableDictionary* processInfo = nil;
    
    //get process info
    processInfo = [self getProcessInfo:flow];
    
    //json?
    if(YES == [appArgs containsObject:ARGS_JSON])
    {
        //output as JSON
        os_log(logHandle, "%{public}@", [self toJSON:packet processInfo:processInfo]);
    }
    
    //output process, then packet via dns_print_reply()
    else
    {
        //output to log
        os_log(logHandle, "PROCESS:\n%{public}@\n", processInfo);
        
        //open fp stream
        fp = open_memstream((char **)&bytes, &length);
        
        //print to stream
        dns_print_reply(packet, fp, 0xFFFF);
        
        //flush
        fflush(fp);
        
        //rewind
        rewind(fp);
        
        //output to log
        os_log(logHandle, "PACKET:\n%{public}s\n", bytes);
        
        //close
        fclose(fp);
    }
    
    return;
}

//convert a packet to JSON
// note, this is basically dns_print_reply, but json-ified
-(NSString*)toJSON:(dns_reply_t*)packet processInfo:(NSMutableDictionary*)processInfo
{
    //output
    NSString* json = nil;
    
    //json data
    NSData* data = nil;
    
    //value
    NSString* value = nil;
    
    //formatted packet
    NSMutableDictionary* formattedPacket = nil;
    
    //header
    dns_header_t* header = nil;
    
    //options
    NSJSONWritingOptions options = 0;
   
    //error
    NSError* error = nil;
    
    //server buffer
    char serverBuffer[1024] = {0};
    
    //server offset
    uint32_t serverOffset = 0;

    //init
    formattedPacket = [NSMutableDictionary dictionary];
    
    //sanity check
    if(packet == NULL)
    {
        //set error
        formattedPacket[@"Error"] = @"Packet is NULL";
        goto bail;
    }
    
    //error?
    if(packet->status != DNS_STATUS_OK)
    {
        //format
        switch (packet->status)
        {
            //timeout
            case DNS_STATUS_TIMEOUT:
                formattedPacket[@"Error"] = @"DNS_STATUS_TIMEOUT";
                break;
              
            //send failed
            case DNS_STATUS_SEND_FAILED:
                formattedPacket[@"Error"] = @"DNS_STATUS_SEND_FAILED";
                break;
             
            //recv failed
            case DNS_STATUS_RECEIVE_FAILED:
                formattedPacket[@"Error"] = @"DNS_STATUS_RECEIVE_FAILED";
                break;
              
            //all others...
            default:
                formattedPacket[@"Error"] = [NSNumber numberWithUnsignedInt:packet->status];
                break;
        }
        
        goto bail;
    }
    
    //init header
    header = packet->header;
    
    //XID
    formattedPacket[@"XID"] = [NSNumber numberWithUnsignedShort:header->xid];

    //QR
    // query
    if(DNS_FLAGS_QR_QUERY == (header->flags & DNS_FLAGS_QR_MASK))
    {
        //add
        formattedPacket[@"QR"] = @"Query";
    }
    //QR
    // reply
    else
    {
        //add
        formattedPacket[@"QR"] = @"Reply";
    }
    
    //server
    // usually null
    if(NULL != packet->server)
    {
        //clear
        memset(serverBuffer, 0, sizeof(serverBuffer));
        
        //offset: AF_INET
        if(AF_INET == packet->server->sa_family)
        {
            serverOffset = INET_NTOP_AF_INET_OFFSET;
        }
        //offset: AF_INET6
        else if(AF_INET6 == packet->server->sa_family)
        {
            serverOffset = INET_NTOP_AF_INET6_OFFSET;
        }
        
        //convert server
        if(nil != (value = [NSString stringWithUTF8String:inet_ntop(packet->server->sa_family, (char *)(packet->server) + serverOffset, serverBuffer, sizeof(serverBuffer)-1)]))
        {
            //add
            formattedPacket[@"Server"] = value;
        }
    }
    
    //opcode
    switch (header->flags & DNS_FLAGS_OPCODE_MASK)
    {
        case ns_o_query:
            formattedPacket[@"Opcode"] = @"Standard";
            break;
        
        case ns_o_iquery:
            formattedPacket[@"Opcode"] = @"Inverse";
            break;
            
        case ns_o_status:
            formattedPacket[@"Opcode"] = @"Status";
            break;
            
        case ns_o_notify:
            formattedPacket[@"Opcode"] = @"Notify";
            break;

        case ns_o_update:
            formattedPacket[@"Opcode"] = @"Update";
            break;

        default:
            formattedPacket[@"Opcode"] = [NSNumber numberWithUnsignedShort:(uint16_t)((header->flags & DNS_FLAGS_OPCODE_MASK) >> 11)];
    }
    
    //flags: AA
    if(header->flags & DNS_FLAGS_AA)
    {
        //add
        formattedPacket[@"AA"] = @"Authoritative";
    }
    else
    {
        //add
        formattedPacket[@"AA"] = @"Non-Authoritative";
    }
    
    //flags: TC
    if(header->flags & DNS_FLAGS_TC)
    {
        //add
        formattedPacket[@"TC"] = @"Truncated";
    }
    else
    {
        //add
        formattedPacket[@"TC"] = @"Non-Truncated";
    }
    
    //flags: RD
    if(header->flags & DNS_FLAGS_RD)
    {
        //add
        formattedPacket[@"RD"] = @"Recursion desired";
    }
    else
    {
        //add
        formattedPacket[@"RD"] = @"No recursion desired";
    }
    
    //flags: RA
    if(header->flags & DNS_FLAGS_RA)
    {
        //add
        formattedPacket[@"RA"] = @"Recursion available";
    }
    else
    {
        //add
        formattedPacket[@"RA"] = @"No recursion available";
    }

    //flags: rcode
    switch (header->flags & DNS_FLAGS_RCODE_MASK)
    {
        case ns_r_noerror:
            formattedPacket[@"Rcode"] = @"No error";
            break;

        case ns_r_formerr:
            formattedPacket[@"Rcode"] = @"Format error";
            break;
            
        case ns_r_servfail:
            formattedPacket[@"Rcode"] = @"Server failure";
            break;
            
        case ns_r_nxdomain:
            formattedPacket[@"Rcode"] = @"Name error";
            break;
            
        case ns_r_notimpl:
            formattedPacket[@"Rcode"] = @"Not implemented";
            break;
            
        case ns_r_refused:
            formattedPacket[@"Rcode"] = @"Refused";
            break;
            
        case ns_r_yxdomain:
            formattedPacket[@"Rcode"] = @"Name exists";
            break;
            
        case ns_r_yxrrset:
            formattedPacket[@"Rcode"] = @"RR Set exists";
            break;
            
        case ns_r_nxrrset:
            formattedPacket[@"Rcode"] = @"RR Set does not exist";
            break;
            
        case ns_r_notauth:
            formattedPacket[@"Rcode"] = @"Not authoritative";
            break;
            
        case ns_r_notzone:
            formattedPacket[@"Rcode"] = @"Record zone does not match section zone";
            break;
            
        case ns_r_badvers:
            formattedPacket[@"Rcode"] = @"Invalid EDNS version or TSIG signature";
            break;
            
        case ns_r_badkey:
            formattedPacket[@"Rcode"] = @"Invalid key";
            break;
            
        case ns_r_badtime:
            formattedPacket[@"Rcode"] = @"Invalid time";
            break;
            
        default:
            formattedPacket[@"Rcode"] = [NSNumber numberWithUnsignedShort:(uint16_t)(header->flags & DNS_FLAGS_RCODE_MASK)];
    }
    
    //add questions
    if(0 != header->qdcount)
    {
        //questions
        NSMutableArray* questions = nil;
        
        //init
        questions = [NSMutableArray array];
        
        //add each question
        for(uint16_t i = 0; i < header->qdcount; i++)
        {
            //question
            NSMutableDictionary* question = nil;
            
            //init
            question = [NSMutableDictionary dictionary];
            
            //name
            if(NULL != packet->question[i]->name)
            {
                //add
                question[@"Question Name"] = [NSString stringWithUTF8String:packet->question[i]->name];
            }
            
            //class
            if(nil != (value = [NSString stringWithUTF8String:dns_class_string(packet->question[i]->dnsclass)]))
            {
                question[@"Question Class"] = value;
            }
            
            //type
            if(nil != (value = [NSString stringWithUTF8String:dns_type_string(packet->question[i]->dnstype)]))
            {
                question[@"Question Type"] = value;
            }
            
            //add
            [questions addObject:question];
        }

        //add questions
        formattedPacket[@"Questions"] = questions;
    }
    
    //add answers
    if(0 != header->ancount)
    {
        //answers
        NSMutableArray* answers = nil;
        
        //init
        answers = [NSMutableArray array];
        
        //add each answer
        for(uint16_t i = 0; i < header->ancount; i++)
        {
            //add
            [answers addObject:[self formatRecord:packet->answer[i]]];
        }
        
        //add answers
        formattedPacket[@"Answers"] = answers;
    }
    
    //add authorties
    if(0 != header->nscount)
    {
        //authorities
        NSMutableArray* authorities = nil;
        
        //init
        authorities = [NSMutableArray array];
        
        //add each authority
        for(uint16_t i = 0; i < header->nscount; i++)
        {
            //add
            [authorities addObject:[self formatRecord:packet->authority[i]]];
        }
        
        //add authorities
        formattedPacket[@"Authorities"] = authorities;
    }
    
    //add additional records
    if(0 != header->arcount)
    {
        //additional records
        NSMutableArray* additionalRecords = nil;
        
        //init
        additionalRecords = [NSMutableArray array];
        
        //add each additional records
        for(uint16_t i = 0; i < header->arcount; i++)
        {
            //add
            [additionalRecords addObject:[self formatRecord:packet->additional[i]]];
        }
        
        //add additional records
        formattedPacket[@"Additional Records"] = additionalRecords;
    }
    
    //pretty print?
    if(YES == [appArgs containsObject:@"-pretty"])
    {
        //set
        options = NSJSONWritingPrettyPrinted;
    }
    
    //convert to JSON
    // wrap since we are serializing JSON
    @try
    {
        //serialize
        data = [NSJSONSerialization dataWithJSONObject:@{@"Process":processInfo, @"Packet":formattedPacket} options:options error:&error];
        if(nil == data)
        {
            //bail
            goto bail;
        }
    }
    //ignore exceptions
    @catch(NSException *exception)
    {
        //bail
        goto bail;
    }

    //convert to string
    json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
bail:
    
    //anny errors?
    if(0 == json.length)
    {
        //set error msg
        json = @"{\"ERROR\": \"Failed to convert packet to JSON\"";
    }
    
    return json;
}

//build a (printable) dictionary from a dns record
// inspired by the 'dns_print_resource_record_lock' function
-(NSMutableDictionary*)formatRecord:(const dns_resource_record_t*)record
{
    //formatted record
    NSMutableDictionary* formattedRecord = nil;
    
    //value
    NSString* value = nil;
    
    //ipv6
    struct sockaddr_in6 s6 = {0};
    
    //buffer
    char hostBuffer[INET6_ADDRSTRLEN+1] = {0};

    //init
    formattedRecord = [NSMutableDictionary dictionary];
    
    //name
    if(nil != (value = [NSString stringWithUTF8String:record->name]))
    {
        //add
        formattedRecord[@"Name"] = value;
    }
    
    //class
    if(nil != (value = [NSString stringWithUTF8String:dns_class_string(record->dnsclass)]))
    {
        //add
        formattedRecord[@"Class"] = value;
    }
    
    //type
    if(nil != (value = [NSString stringWithUTF8String:dns_class_string(record->dnstype)]))
    {
        //add
        formattedRecord[@"Type"] = value;
    }
    
    //handle specific types
    switch(record->dnstype)
    {
        //host (IPv4)
        case ns_t_a:
            
            //check / add
            if(nil != (value = [NSString stringWithUTF8String:inet_ntoa(record->data.A->addr)]))
            {
                //add
                formattedRecord[@"Host Address"] = value;
            }
            
            break;
            
        //host (IPv6)
        case ns_t_aaaa:
            
            //clear
            memset(&s6, 0, sizeof(struct sockaddr_in6));
            
            //init
            s6.sin6_len = sizeof(struct sockaddr_in6);
            s6.sin6_family = AF_INET6;
            s6.sin6_addr = record->data.AAAA->addr;
            
            //host
            if(nil != (value = [NSString stringWithUTF8String:inet_ntop(AF_INET6, (char *)(&s6) + INET_NTOP_AF_INET6_OFFSET, hostBuffer, INET6_ADDRSTRLEN)]))
            {
                //add
                formattedRecord[@"Host Address"] = value;
            }
            
            break;
            
        //cname etc
        case ns_t_md:
        case ns_t_mf:
        case ns_t_cname:
        case ns_t_mb:
        case ns_t_mg:
        case ns_t_mr:
        case ns_t_ptr:
        case ns_t_ns:
            
            //check / add
            if(NULL != record->data.CNAME->name)
            {
                //add
                formattedRecord[@"Canonical Name"] = [NSString stringWithUTF8String:record->data.CNAME->name];
            }
        
            break;
        
        //txt
        case ns_t_txt:
        {
            //txt records
            NSMutableArray* txtRecords = nil;
            
            //init
            txtRecords = [NSMutableArray array];
        
            //add each TXT
            for(int i = 0; i < record->data.TXT->string_count; i++)
            {
                //check / add
                if(NULL != record->data.TXT->strings[i])
                {
                    //add
                    [txtRecords addObject:[NSString stringWithUTF8String:record->data.TXT->strings[i]]];
                }
            }
            
            //add additional records
            formattedRecord[@"TXT Records"] = txtRecords;
            
            break;
        }
            
        default:
            break;
    }
    
    return formattedRecord;
}


@end




