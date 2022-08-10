//
//  DNSProxyProvider.m
//  DNSMonitor (Extension)
//
//  Created by Patrick Wardle on 7/26/22.
//  Copyright © 2022 Objective-See. All rights reserved.
//

//https://developer.apple.com/forums/thread/75893

#import "DNSProxyProvider.h"

//log handle
extern os_log_t logHandle;

//extract a DNS url
NSMutableString* extractDNSName(unsigned char* start, unsigned char* chunk, unsigned char* end)
{
    //size of chunk
    NSUInteger chunkSize = 0;
    
    //name
    NSMutableString* name = nil;
    
    //alloc
    name = [NSMutableString string];
    
    //parse
    while(YES)
    {
        //grab size & check
        chunkSize = (*chunk & 0xFF);
        if(chunk+chunkSize >= end)
        {
            //bail
            goto bail;
        }
        
        //skip size
        chunk++;
        if(chunk >= end)
        {
            //bail
            goto bail;
        }
        
        //append each byte of url chunk
        for(NSUInteger i = 0; i < chunkSize; i++)
        {
            //add byte
            [name appendFormat:@"%c", chunk[i]];
        }
        
        //next chunk
        chunk += chunkSize;
        if(chunk >= end)
        {
            //bail
            goto bail;
        }
        
        //done when hit a NULL
        if(0x0 == *chunk)
        {
            //done
            break;
        }
        
        //append dot
        [name appendString:@"."];
        
        //if value is 0xC
        // go to that new chunk offset
        if(0xC0 == *chunk)
        {
            //skip ptr (0xCC)
            chunk++;
            if(chunk >= end)
            {
                //bail
                goto bail;
            }
            
            //go to next chunk
            chunk = (unsigned char*)start + (*chunk & 0xFF);
            if(chunk >= end)
            {
                //bail
                goto bail;
            }
        }
    }
    
bail:
    
    return name;
}

//convert IP addr to (ns)string
// from: https://stackoverflow.com/a/29147085/3854841
NSString* convertIPAddr(unsigned char* ipAddr, __uint8_t socketFamily)
{
    //string
    NSString* socketDescription = nil;
    
    //socket address
    unsigned char socketAddress[INET6_ADDRSTRLEN+1] = {0};
    
    //what family?
    switch(socketFamily)
    {
        //IPv4
        case AF_INET:
        {
            //convert
            inet_ntop(AF_INET, ipAddr, (char*)&socketAddress, INET_ADDRSTRLEN);
            
            break;
        }
            
        //IPV6
        case AF_INET6:
        {
            //convert
            inet_ntop(AF_INET6, ipAddr, (char*)&socketAddress, INET6_ADDRSTRLEN);
            
            break;
        }
            
        default:
            break;
    }
    
    //convert to obj-c string
    if(0 != strlen((const char*)socketAddress))
    {
        //convert
        socketDescription = [NSString stringWithUTF8String:(const char*)socketAddress];
    }
    
    return socketDescription;
}


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
    os_log_debug(logHandle, "method '%s' invoked", __PRETTY_FUNCTION__);
    
    //call completion handler
    completionHandler(nil);
    
    return;
    
}

//stop proxy
-(void)stopProxyWithReason:(NEProviderStopReason)reason
          completionHandler:(void (^)(void))completionHandler
{
    //dbg msg
    os_log_debug(logHandle, "method '%s' invoked", __PRETTY_FUNCTION__);
    
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
    //TODO: handle TCP!
    //not UDP flow
    else
    {
        //dbg msg
        os_log_error(logHandle, "ERROR: %{public}@ is an unsupported flow type (will drop)", flow.className);
        
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
               
                //error?
                if(nil != receive_error)
                {
                    os_log_error(logHandle, "ERROR, nw_connection_receive failed with:  %d", nw_error_get_error_code(receive_error));
                    
                    return;
                }
            
                //parse response
                [self parseDNS:(NSData*)content];
                
                //write to flow
                [flow writeDatagrams:@[(NSData*)content] sentByEndpoints:@[endpoint] completionHandler:^(NSError *error)
                {
                    if(nil != error)
                    {
                        os_log_debug(logHandle, "writeDatagrams ERROR: %{public}@", error);
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
            os_log_error(logHandle, "ERROR, 'readDatagramsWithCompletionHandler' failed with: %{public}@", error);
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
            //endpoint, connection, etc
            nw_endpoint_t endpoint = nil;
            nw_connection_t connection = nil;
            
            //first parse request
            // just want DNS questions
            [self parseDNS:(NSData*)datagrams[i]];
            
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
                    os_log_error(logHandle, "ERROR, 'nw_connection_set_state_changed_handler' failed with: %d", nw_error_get_error_code(error));
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
                                os_log_error(logHandle, "ERROR, 'nw_connection_send' failed with: %d", nw_error_get_error_code(error));
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

//parse a DNS request
// extract question (url)
-(void)parseDNSRequest:(NSData*)datagram
{
    //dns header
    struct dnsHeader* dnsHeader = NULL;
    
    //end of response
    unsigned char* end = NULL;
    
    //dns data
    unsigned char* dnsData = NULL;
    
    //offset to name
    NSUInteger nameOffset = 0;
    
    //question
    NSString* question = nil;

    //typecast
    dnsHeader = (struct dnsHeader*)datagram.bytes;
    
    //init end
    end = (unsigned char*)datagram.bytes+datagram.length;
    
    //print out DNS request
    //for(int i = 0; i<datagram.length; i++)
    //  logMsg(LOG_DEBUG, [NSString stringWithFormat:@"%d/%02x", i, datagram.bytes[i] & 0xFF]);
    
    //init pointer to DNS data
    // begins right after (fixed) DNS header
    dnsData = (unsigned char*)((unsigned char*)dnsHeader + sizeof(struct dnsHeader));
    if(dnsData >= end)
    {
        //bail
        goto bail;
    }
    
    //sanity check
    // make sure there is a question
    if(0 == ntohs(dnsHeader->qdcount))
    {
        //bail
        goto bail;
    }
    
    //parse question entries
    for(NSUInteger i = 0; i < ntohs(dnsHeader->qdcount); i++)
    {
        //sanity check
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
        
        //offset
        nameOffset = (unsigned char*)dnsData - (unsigned char*)dnsHeader;
        if(nameOffset >= datagram.length)
        {
            //bail
            goto bail;
        }

        //extact question
        question = extractDNSName((unsigned char*)dnsHeader, (unsigned char*)dnsHeader + nameOffset, end);
        
        //dbg message
        os_log_debug(logHandle, "QUESTION: %{public}@", question);
        
        //skip over name
        dnsData += question.length;
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
        
        //skip question type
        dnsData += sizeof(unsigned short);
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
        
        //skip question class
        dnsData += sizeof(unsigned short);
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
    }
    
bail:
    
    return;
}

//parse a DNS response
// extact DNS answer(s)
-(void)parseDNSResponse:(NSData*)datagram
{
    //dns header
    struct dnsHeader* dnsHeader = NULL;
    
    //end of response
    unsigned char* end = NULL;
    
    //dns data
    unsigned char* dnsData = NULL;
    
    //offset to name
    NSUInteger nameOffset = 0;
    
    //name from CNAME
    NSString* cName = nil;
    
    //name from A/AAAA
    NSString* aName = nil;
    
    //type
    // A, AAAA, etc...
    unsigned short addressType = 0;
    
    //ip address
    NSString* ipAddress = nil;
    
    //typecast
    dnsHeader = (struct dnsHeader*)datagram.bytes;
    
    //ignore any errors
    // bottom (4) bits will be 0x0 for "successful response"
    if(0 != ((ntohs(dnsHeader->flags)) & (1<<(0))))
    {

        //err msg
        // 0x3: no such name
        if(0x3 == ((ntohs(dnsHeader->flags)) & 0x3))
        {
            //err msg
            os_log_error(logHandle, "DNS response error: 'no such name'");
        }
        else
        {
            //err msg
            os_log_error(logHandle, "DNS response error, flags: %#x", ntohs(dnsHeader->flags));
        }

        //bail
        goto bail;
    }
    
    //TODO: handle this?
    //ignore any packets that don't have answers
    if(0 == ntohs(dnsHeader->ancount))
    {
        //dbg msg
        os_log_debug(logHandle, "DNS response contains no answers ('ancount' is zero), though 'nscount' is %#x", ntohs(dnsHeader->nscount));
        
        //bail
        goto bail;
    }
    
    //print out DNS response
    //for(int i = 0; i<datagram.length; i++)
    //  logMsg(LOG_DEBUG, [NSString stringWithFormat:@"%d/%02x", i, datagram.bytes[i] & 0xFF]);

    //init end
    end = (unsigned char*)datagram.bytes+datagram.length;

    //init pointer to DNS data
    // begins right after (fixed) DNS header
    dnsData = (unsigned char*)((unsigned char*)dnsHeader + sizeof(struct dnsHeader));
    if(dnsData >= end)
    {
        //bail
        goto bail;
    }
    
    //skip over any question entries
    // they should always come first, ya?
    for(NSUInteger i = 0; i < ntohs(dnsHeader->qdcount); i++)
    {
        //sanity check
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
        
        //skip over URL
        // look for NULL terminator
        while( (*dnsData++) && (dnsData < end));
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
        
        //skip question type
        dnsData += sizeof(unsigned short);
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
        
        //skip question class
        dnsData += sizeof(unsigned short);
        if(dnsData >= end)
        {
            //bail
            goto bail;
        }
    }
    
    //now, parse answers
    // this is all we really care about...
    for(NSUInteger i = 0; i < ntohs(dnsHeader->ancount); i++)
    {
        //sanity check
        // answers should be at least 0xC
        if(dnsData+0xC >= end)
        {
            //bail
            goto bail;
        }
        
        //first byte should always indicate 'offset'
        if(0xC0 != *dnsData++)
        {
            //bail
            goto bail;
        }
        
        //extract name offset
        nameOffset = *dnsData++ & 0xFF;
        if(nameOffset >= datagram.length)
        {
            //bail
            goto bail;
        }
        
        //extract address type
        addressType = ntohs(*(unsigned short*)dnsData);
        
        //only process certain addr types
        // A (0x1), CNAME (0x5), and AAAA (0x1C)
        if( (0x1 != addressType) &&
            (0x5 != addressType) &&
            (0x1C != addressType) )
        {
            
            //debug
            os_log_debug(logHandle, "DNS response, %#x is (currently) an unsupported address type", addressType);
            
            //bail
            goto bail;
        }
        
        //skip over type
        dnsData += sizeof(unsigned short);

        //skip class
        dnsData += sizeof(unsigned short);
        
        //skip ttl
        dnsData += sizeof(unsigned int);
        
        //address type: CNAME
        // extact (first) instance of name
        if(0x5 == addressType)
        {
            //only extract first
            if(nil == cName)
            {
                //extact name
                cName = extractDNSName((unsigned char*)dnsHeader, (unsigned char*)dnsHeader + nameOffset, end);
            }
            
            //skip over size + length of data
            dnsData += sizeof(unsigned short) + ntohs(*(unsigned short*)dnsData);
        }
        
        //type A
        else if(0x1 == addressType)
        {
            //extact name
            // but only if we don't have one from the first cname
            if(nil == cName)
            {
                //extract
                aName = extractDNSName((unsigned char*)dnsHeader, (unsigned char*)dnsHeader + nameOffset, end);
            }
            
            //length should be 4
            if(0x4 != ntohs(*(unsigned short*)dnsData))
            {
                //bail
                goto bail;
            }
            
            //skip over length
            dnsData += sizeof(unsigned short);
            
            //ipv4 addr is 0x4
            if(dnsData+0x4 > end)
            {
                //bail
                goto bail;
            }
            
            //covert
            ipAddress = convertIPAddr(dnsData, AF_INET);
            
            //skip over IP address
            // for IPv4 addresses, this will always be 4
            dnsData += 0x4;
        }
        
        //type AAAA
        else if(0x1C == addressType)
        {
            //extact name
            // but only if we don't have one from the first cname
            if(nil == cName)
            {
                //extract
                aName = extractDNSName((unsigned char*)dnsHeader, (unsigned char*)dnsHeader + nameOffset, end);
            }
            
            //length should be 0x10
            if(0x10 != ntohs(*(unsigned short*)dnsData))
            {
                //bail
                goto bail;
            }
            
            //skip over length
            dnsData += sizeof(unsigned short);
            
            //ipv6 addr is 0x10
            if(dnsData+0x10 >= end)
            {
                //bail
                goto bail;
            }
            
            //convert
            ipAddress = convertIPAddr(dnsData, AF_INET6);
            
            //skip over IP address
            // for IPv4 addresses, this will always be 0x10
            dnsData += 0x10;
        }
        
        //add to DNS 'cache'
        if(0 != ipAddress.length)
        {
            //default to first cName
            if(nil != cName)
            {
                //add to cache
                [self.dnsCache setObject:cName forKey:ipAddress];
                
                //dbg msg
                os_log_debug(logHandle, "ANSWER (cName): %{public}@ -> %{public}@", cName, ipAddress);
            }
            //otherwise
            // use aName
            else if(nil != aName)
            {
                //add to cache
                [self.dnsCache setObject:aName forKey:ipAddress];
                
                //dbg msg
                os_log_debug(logHandle, "ANSWER (aName): %{public}@ -> %{public}@", aName, ipAddress);
            }
        }
        
    }//parse answers
    
bail:
    
    return;
}

//parse a DNS packet
-(void)parseDNS:(NSData*)datagram
{
    //dns header
    struct dnsHeader* dnsHeader = NULL;
    
    //sanity check
    if(datagram.length < sizeof(struct dnsHeader))
    {
        //bail
        goto bail;
    }
    
    //typecast
    dnsHeader = (struct dnsHeader*)datagram.bytes;
    
    //request?
    // top bit flag will be 0x0 for request
    if(0 == ((ntohs(dnsHeader->flags)) & (1<<(15))))
    {
        //parse request
        [self parseDNSRequest:datagram];
    }
    //response
    else
    {
        //parse response
        [self parseDNSResponse:datagram];
    }
    
bail:
    
    return;
}

@end
