//
//  DNSProxyProvider.m
//  DNSMonitor (Extension)
//
//  Created by Patrick Wardle on 7/26/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

//https://developer.apple.com/forums/thread/75893

#import <nameser.h>
#import <dns_util.h>
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

/* GLOBALS */

//log handle
extern os_log_t logHandle;

//(app's) arguments
extern NSMutableArray* appArgs;

@implementation DNSProxyProvider

@synthesize dnsCache;

//start proxy
-(void)startProxyWithOptions:(NSDictionary<NSString *,id> *)options
            completionHandler:(void (^)(NSError *error))completionHandler
{
    //init DNS 'cache'
    dnsCache = [[NSCache alloc] init];
            
    //set cache limit
    self.dnsCache.countLimit = 1024;
    
    //dbg msg
    if(YES != [appArgs containsObject:@"-json"])
    {
        os_log(logHandle, "method '%s' invoked", __PRETTY_FUNCTION__);
    }
    
    //call completion handler
    completionHandler(nil);
    
    return;
    
}

//stop proxy
-(void)stopProxyWithReason:(NEProviderStopReason)reason
          completionHandler:(void (^)(void))completionHandler
{
    //dbg msg
    if(YES != [appArgs containsObject:@"-json"])
    {
        os_log(logHandle, "method '%s' invoked", __PRETTY_FUNCTION__);
    }
    
    //call completion handler
    completionHandler();
    
    return;
}

//handle new flow
// for now, we only support UDP
-(BOOL)handleNewFlow:(NEAppProxyFlow *)flow
{
    //flag
    BOOL handled = NO;
    
    //is a UDP flow?
    // if so, open connection/handle flow
    if(YES == [flow isKindOfClass:[NEAppProxyUDPFlow class]])
    {
        //open flow
        [(NEAppProxyUDPFlow*)flow openWithLocalEndpoint:(NWHostEndpoint*)((NEAppProxyUDPFlow*)flow).localEndpoint completionHandler:^(NSError *error) {
                
            if(error == nil)
            {
                //read from flow
                // and send to remote endpoint
                [self flowOut:(NEAppProxyUDPFlow*)flow];
            }
            
        }];
        
        //set flag
        handled = YES;
    }
    //TODO: handle TCP
    //flow is not a UDP flow
    else
    {
        //err msg
        if(YES != [appArgs containsObject:@"-json"])
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
    
    return handled;
}

//read from (remote) endpoint, then write to flow
-(void)flowIn:(NEAppProxyUDPFlow*)flow connection:(nw_connection_t)connection endpoint:(NWHostEndpoint*)endpoint
{
    //read from (remote) connection
    nw_connection_receive(connection, 1, UINT32_MAX,
        ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {
        
                //packet
                NSData* packet = nil;
        
                //parsed packet
                dns_reply_t* parsedPacket = NULL;
        
                //error?
                if(nil != receive_error)
                {
                    //err msg
                    if(YES != [appArgs containsObject:@"-json"])
                    {
                        os_log_error(logHandle, "ERROR: nw_connection_receive failed with %d", nw_error_get_error_code(receive_error));
                    }
                    return;
                }
        
                //extract packet
                packet = (NSData*)content;
                
                //parse & print
                parsedPacket = dns_parse_packet([packet bytes], (uint32_t)packet.length);
                if(NULL != parsedPacket)
                {
                    //print
                    [self printPacket:parsedPacket];
                    
                    //free
                    dns_free_reply(parsedPacket);
                }
        
                //write to flow
                [flow writeDatagrams:@[(NSData*)content] sentByEndpoints:@[endpoint] completionHandler:^(NSError *error)
                {
                    //error?
                    if(nil != error)
                    {
                        //err msg
                        if(YES != [appArgs containsObject:@"-json"])
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
-(void)flowOut:(NEAppProxyUDPFlow*)flow {

    //read from flow
    [flow readDatagramsWithCompletionHandler:^(NSArray * datagrams, NSArray * endpoints, NSError *error){
        
        //error?
        if(nil != error)
        {
            //err msg
            if(YES != [appArgs containsObject:@"-json"])
            {
                os_log_error(logHandle, "ERROR: 'readDatagramsWithCompletionHandler' failed with %{public}@", error);
            }
            
            return;
        }
        
        //ended?
        // close up
        if(0 == datagrams.count)
        {
            //close
            [flow closeReadWithError:error];
            [flow closeWriteWithError:error];
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
            parsedPacket = dns_parse_packet([packet bytes], (uint32_t)packet.length);
            if(NULL != parsedPacket)
            {
                //print
                [self printPacket:parsedPacket];
                
                //free
                dns_free_reply(parsedPacket);
            }
            
            //create an (nw_)endpoint
            endpoint = nw_endpoint_create_host(((NWHostEndpoint*)endpoints[i]).hostname.UTF8String, ((NWHostEndpoint*)endpoints[i]).port.UTF8String);
            
            //create connection
            connection = nw_connection_create(endpoint, nw_parameters_create_secure_udp( NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION));
            
            //set queue
            nw_connection_set_queue(connection, dispatch_get_main_queue());
            
            //set handler
            // will be invoked with various states
            nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
                
                //error?
                if(NULL != error)
                {
                    //err msg
                    if(YES != [appArgs containsObject:@"-json"])
                    {
                        os_log_error(logHandle, "ERROR: 'nw_connection_set_state_changed_handler' failed with %d", nw_error_get_error_code(error));
                    }
                    
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
                        nw_connection_send(connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
                            
                            //error
                            if(NULL != error)
                            {
                                //err msg
                                if(YES != [appArgs containsObject:@"-json"])
                                {
                                    os_log_error(logHandle, "ERROR: 'nw_connection_send' failed with %d", nw_error_get_error_code(error));
                                }
                                
                                return;
                            }
                            
                        });
                        
                        //now read from remote connection and write to (local) flow
                        [self flowIn:flow connection:connection endpoint:endpoints[i]];
                        
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

//print a packet
// app's args control verbosity/format
-(void)printPacket:(dns_reply_t*)packet
{
    //file pointer
    FILE *fp = NULL;
    
    //bytes
    char *bytes = NULL;
    
    //size
    size_t length = 0;
    
    //json?
    if(YES == [appArgs containsObject:@"-json"])
    {
        //output as JSON
        os_log(logHandle, "%{public}@", [self toJSON:packet]);
    }
    
    //output packet via dns_print_reply
    else
    {
        //open fp stream
        fp = open_memstream((char **)&bytes, &length);
        
        //print to stream
        dns_print_reply(packet, fp, 0xFFFF);
        
        //flush/rewind
        fflush(fp);
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
-(NSString*)toJSON:(dns_reply_t*)packet
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
        data = [NSJSONSerialization dataWithJSONObject:formattedPacket options:options error:&error];
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
    char hostBuffer[0x100] = {0};

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
    // TODO: add all/more types
    switch(record->dnstype)
    {
        //host (IPv4)
        case ns_t_a:
            
            //host
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
            if(nil != (value = [NSString stringWithUTF8String:inet_ntop(AF_INET6, (char *)(&s6) + INET_NTOP_AF_INET6_OFFSET, hostBuffer, 64)]))
            {
                //add
                formattedRecord[@"Host Address"] = value;
            }
            
            break;
            
        //cname
        case ns_t_cname:
        
            //cname
            if(nil != (value = [NSString stringWithUTF8String:record->data.CNAME->name]))
            {
                //add
                formattedRecord[@"Canonical Name"] = value;
            }
        
            break;
            
        default:
            break;
    }
    
    return formattedRecord;
}

@end
