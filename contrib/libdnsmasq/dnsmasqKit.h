//
//  dnsmasqKit.h
//  dnsmasq
//
//  Created by Alex Gray on 5/27/14.
//  Copyright (c) 2014 Alex Gray. All rights reserved.
//

//#import <AtoZSingleton.h>

#import <Foundation/Foundation.h>

@interface MasqKit : NSObject // AtoZSingleton

+ (instancetype) shared;

+ (void) monitorFile:(NSString*)path then:(void(^)(NSString*))dothis;

@property (readonly) NSDictionary *info;

@end
