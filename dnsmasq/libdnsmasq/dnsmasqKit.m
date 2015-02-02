//
//  dnsmasqKit.m
//  dnsmasq
//
//  Created by Alex Gray on 5/27/14.
//  Copyright (c) 2014 Alex Gray. All rights reserved.
//

#import "dnsmasq.h"

@interface dnsmasqKit ()
@property NSMutableDictionary *map;
@end

static dnsmasqKit* singleton = nil;

@implementation dnsmasqKit {  }


+ (instancetype) shared { static dispatch_once_t uno;

  NSLog(@"dispatching %@ singleton!", NSStringFromClass([self class]));

  dispatch_once(&uno, ^{
    singleton = [[self.class alloc] init];
    singleton.map = @{}.mutableCopy;
  });
  return singleton;
}

+ (void) monitorFile:(NSString*)path then:(void(^)(NSString*))dothis {

  ((dnsmasqKit*)self.shared).map[path] = [dothis copy];
  [self monitorFile:path];
}

+ (void)monitorFile:(NSString*) path {


  int fdes = open([path UTF8String], O_RDONLY);
  dispatch_queue_t queue = dispatch_get_global_queue(0, 0);

  void (^eventHandler)(void), (^cancelHandler)(void);
  unsigned long mask = DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_ATTRIB | DISPATCH_VNODE_LINK | DISPATCH_VNODE_RENAME | DISPATCH_VNODE_REVOKE;
  __block dispatch_source_t source;

  eventHandler = ^{
    unsigned long l = dispatch_source_get_data(source);
    if (l & DISPATCH_VNODE_DELETE) {
      NSLog(@"watched file deleted!  cancelling source\n");
      dispatch_source_cancel(source);
    }
    else {
      // handle the file has data case
      NSLog(@"watched file has data\n");
    }
  };
  cancelHandler = ^{
    int fdes = dispatch_source_get_handle(source);
    close(fdes);
    // Wait for new file to exist.
    while ((fdes = open([path UTF8String], O_RDONLY)) == -1)
      sleep(1);
    printf("re-opened target file in cancel handler\n");
    source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fdes, mask, queue);
    dispatch_source_set_event_handler(source, eventHandler);
    dispatch_source_set_cancel_handler(source, cancelHandler);
    dispatch_resume(source);
  };

  source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE,fdes, mask, queue);
  dispatch_source_set_event_handler(source, eventHandler);
  dispatch_source_set_cancel_handler(source, cancelHandler);
  dispatch_resume(source);
//  dispatch_main();


//  dispatch_queue_t queue = dispatch_queue_create( "com.example.unique.identifier", NULL );


 
//  dispatch_release( exampleQueue );
/*
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    int fildes = open([path UTF8String], O_EVTONLY);

    __block __typeof(self) blockSelf = self;
    __block dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fildes,
               DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE | DISPATCH_VNODE_EXTEND | 
               DISPATCH_VNODE_ATTRIB | DISPATCH_VNODE_LINK | DISPATCH_VNODE_RENAME | 
               DISPATCH_VNODE_REVOKE, queue);
    dispatch_source_set_event_handler(source, ^{
                                          unsigned long flags = dispatch_source_get_data(source);
                                          if(flags & DISPATCH_VNODE_DELETE)
                                          {
                                              dispatch_source_cancel(source);
                                              //        
                                              // DO WHAT YOU NEED HERE
                                              //
                                              void(^m)(NSString*) = [[self shared]map] [path];
                                              if (m) m(path);

                                              [blockSelf monitorFile:path];
                                          }
                                      });
    dispatch_source_set_cancel_handler(source, ^(void) {
                                          close(fildes);
                                      });
    dispatch_resume(source);
*/
}
@end
