
@import AppKit;
@import Darwin;

#ifndef DNSMASQ_COMPILE_OPTS
#define DNSMASQ_COMPILE_OPTS 1
#endif

#import <dnsmasq.h>

int main (int argc, char **argv) {

  int status = NULL;

  @autoreleasepool { while ((status = dnsmasq(argc, argv)) == NULL) { ;; }  } return status;

}


