//
//  KBDrupalConnect.m
//
// ***** BEGIN LICENSE BLOCK *****
// Version: MPL 1.1/GPL 2.0
//
// The contents of this file are subject to the Mozilla Public License Version
// 1.1 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
// http://www.mozilla.org/MPL/
//
// Software distributed under the License is distributed on an "AS IS" basis,
// WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
// for the specific language governing rights and limitations under the
// License.
//
// The Original Code is Kyle Browning, released June 27, 2010.
//
// The Initial Developer of the Original Code is
// Kyle Browning
// Portions created by the Initial Developer are Copyright (C) 2010
// the Initial Developer. All Rights Reserved.
//
// Contributor(s):
//
// Alternatively, the contents of this file may be used under the terms of
// the GNU General Public License Version 2 or later (the "GPL"), in which
// case the provisions of the GPL are applicable instead of those above. If
// you wish to allow use of your version of this file only under the terms of
// the GPL and not to allow others to use your version of this file under the
// MPL, indicate your decision by deleting the provisions above and replacing
// them with the notice and other provisions required by the GPL. If you do
// not delete the provisions above, a recipient may use your version of this
// file under either the MPL or the GPL.
//
// ***** END LICENSE BLOCK *****
#import <CommonCrypto/CommonHMAC.h> //for kCCHmacAlgSHA256
#import <CommonCrypto/CommonDigest.h> //for CC_SHA256_DIGEST_LENGTH
#import "KBDrupalConnect.h"

@implementation KBDrupalConnect
@synthesize connResult, sessid, method, params, userInfo;
- (id) init {
    [super init];
    isRunning = NO;
    mainTimer = nil;
    if(params == nil) {
        NSMutableDictionary *newParams = [[NSMutableDictionary alloc] init];
        params = newParams;
    }
    [self connect];
    return self;
}
//Use this, if you have already connected to Drupal, for example, if the user is logged in, you should
//Store that session id somewhere and use it anytime you need to make a new drupal call.
//KBDrupalConnect should handle there rest.
- (id) initWithSessId:(NSString*)aSessId {
    [super init];
    isRunning = NO;
    mainTimer = nil;
    if(params == nil) {
        NSMutableDictionary *newParams = [[NSMutableDictionary alloc] init];
        params = newParams;
    }
    [self setSessid:aSessId];
    return self;
}
- (id) initWithUserInfo:(NSDictionary*)someUserInfo andSessId:(NSString*)sessId {
    [super init];
    isRunning = NO;
    mainTimer = nil;
    if(params == nil) {
        NSMutableDictionary *newParams = [[NSMutableDictionary alloc] init];
        params = newParams;
    }
    [self setUserInfo:someUserInfo];
    [self setSessid:sessId];
    return self;
}
- (void) connect {
    [self setMethod:@"system.connect"];
    [self runMethod];
}

- (void) loginWithUsername:(NSString*)userName andPassword:(NSString*)password {
    [self setMethod:@"user.login"];
    [self addParam:@"test" forKey:@"username"];
    [self addParam:@"test" forKey:@"password"];
    [self runMethod];
}

- (void) logout {
    [self setMethod:@"user.logout"];
    [self runMethod];
}

- (void) done:(id)results{
#ifdef DEBUG 
    //NSLog(@"%@", results);
#endif
    if([[[results object] objectForKey:@"#method"] isEqualToString:@"system.connect"]) {
        myDict = [[results object] objectForKey:@"#data"];
        if(myDict != nil) {
            [self setSessid:[myDict objectForKey:@"sessid"]];
            [self setUserInfo:[myDict objectForKey:@"user"]];
        }
    }
    if([[[results object] objectForKey:@"#method"] isEqualToString:@"user.login"]) {
        myDict = [[results object] objectForKey:@"#data"];
        if(myDict != nil) {
            [self setSessid:[myDict objectForKey:@"sessid"]];
            [self setUserInfo:[myDict objectForKey:@"user"]];
        }
    }
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc removeObserver:self];
    isRunning = NO;
}
- (NSString*)stringWithHexBytes:(NSData *)theData {
	NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:([theData length] * 2)];
	const unsigned char *dataBuffer = [theData bytes];
	int i;
	
	for (i = 0; i < [theData length]; ++i)
		[stringBuffer appendFormat:@"%02X", (unsigned long)dataBuffer[ i ]];
	
	return [[stringBuffer copy] autorelease];
}
- (NSString *)generateHash:(NSString *)inputString {
	NSData *key = [DRUPAL_API_KEY dataUsingEncoding:NSUTF8StringEncoding];
	NSData *clearTextData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
	uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
	CCHmacContext hmacContext;
	CCHmacInit(&hmacContext, kCCHmacAlgSHA256, key.bytes, key.length);
	CCHmacUpdate(&hmacContext, clearTextData.bytes, clearTextData.length);
	CCHmacFinal(&hmacContext, digest);
	NSData *hashedData = [NSData dataWithBytes:digest length:32];
	NSString *hashedString = [self stringWithHexBytes:hashedData];
	//NSLog(@"hash string: %@ length: %d",[hashedString lowercaseString],[hashedString length]);
	return [hashedString lowercaseString];
}

-(NSString *) genRandStringLength {
    NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";    
    NSMutableString *randomString = [NSMutableString stringWithCapacity: 10];
    
    for (int i=0; i<10; i++) {
        [randomString appendFormat: @"%c", [letters characterAtIndex: arc4random()%[letters length]]];
    }
    
    return randomString;
}

-(void) runMethod {
    if(isRunning) {
        if (mainTimer == nil) {
            mainTimer = [NSTimer scheduledTimerWithTimeInterval:.5 target:self selector:@selector(runMethod) userInfo:nil repeats:NO];
        } else {
            [mainTimer invalidate];
            mainTimer = [NSTimer scheduledTimerWithTimeInterval:.5 target:self selector:@selector(runMethod) userInfo:nil repeats:NO];
        }
    } else {
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        [nc addObserver:self selector:@selector(done:) name:DRUPAL_METHOD_DONE object:nil];
        NSString *timestamp = [NSString stringWithFormat:@"%d", (long)[[NSDate date] timeIntervalSince1970]];
        NSString *nonce = [self genRandStringLength];
        [self removeParam:@"hash"];
        [self addParam:DRUPAL_DOMAIN forKey:@"domain_name"];
        [self removeParam:@"domain_name"];
        [self removeParam:@"domain_time_stamp"];
        [self removeParam:@"nonce"];
        [self removeParam:@"sessid"];
        NSString *hashParams = [NSString stringWithFormat:@"%@;%@;%@;%@",timestamp,DRUPAL_DOMAIN,nonce,[self method]];
        [self addParam:[self generateHash:hashParams] forKey:@"hash"];
        [self addParam:DRUPAL_DOMAIN forKey:@"domain_name"];
        [self addParam:timestamp forKey:@"domain_time_stamp"];
        [self addParam:nonce forKey:@"nonce"];
        [self addParam:[self sessid] forKey:@"sessid"];
        NSMutableURLRequest *theRequest=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:DRUPAL_SERVICES_URL]
                                                                cachePolicy:NSURLRequestUseProtocolCachePolicy
                                                            timeoutInterval:60.0];
        [theRequest setHTTPMethod:@"POST"];
        NSString *httpBodyString = [[NSString alloc] initWithString:[self buildParams]];
        NSData *myRequestData = [NSData dataWithBytes:[httpBodyString UTF8String] length:[httpBodyString length]];
        [theRequest setHTTPBody:myRequestData];
        NSURLConnection *theConnection=[[NSURLConnection alloc] initWithRequest:theRequest delegate:self];
        if(!theConnection) {
            NSLog(@"CONNETION FAILED!");
        }
        isRunning = YES;
    }
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    [connection release];
    NSLog(@"Connection failed! Error - %@ %@",
          [error localizedDescription],
          [[error userInfo] objectForKey:NSErrorFailingURLStringKey]);
}
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    NSString *returnDataAsString = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
    NSDictionary *dictionary = [returnDataAsString propertyList];
    [self setConnResult:dictionary];
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc postNotificationName:DRUPAL_METHOD_DONE object:[self connResult]];
    isRunning = NO;
}

- (void) setMethod:(NSString *)aMethod {
    method = aMethod;
    if([params objectForKey:@"method"] == nil) {
       [self addParam:aMethod forKey:@"method"];   
    } else {
       [self removeParam:@"method"];
       [self addParam:aMethod forKey:@"method"];
    }
}
- (NSString *) buildParams {
    NSString *finalParams;
    NSMutableArray *arrayofParams = [[NSMutableArray alloc] init];
    NSEnumerator *enumerator = [params keyEnumerator];
    NSString *aKey = nil;
    NSString *value = nil;
    while ( (aKey = [enumerator nextObject]) != nil) {
        value = [params objectForKey:aKey];
        [arrayofParams addObject:[NSString stringWithFormat:@"&%@=%@", aKey, value]];
    }
    finalParams = [arrayofParams componentsJoinedByString:@""];
    NSString *finalParamsString = @"";
    for (NSString *string in arrayofParams) {
        finalParamsString = [finalParamsString stringByAppendingString:string];
    }
    return finalParams;
}
            
- (void) addParam:(id)value forKey:(NSString *)key {
    if(value != nil) {
        [params setObject:value forKey:key];
    }
}
- (void) removeParam:(NSString *)key {
    [params removeObjectForKey:key];
}
- (NSString *)description {
    return [NSString stringWithFormat:@"%@, %@, %@, %@", userInfo, params, sessid, (isRunning ? @"YES" : @"NO")];
}
- (void) dealloc {
    if (mainTimer != nil) {
        [mainTimer invalidate];
        [mainTimer release];
        mainTimer = nil;
    }
    [super dealloc];
}
@end