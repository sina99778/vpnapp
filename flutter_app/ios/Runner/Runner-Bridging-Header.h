// Bridging header — exposes the native C anti-tamper API to Swift.
// Wire this file into the Runner target via Build Settings:
//   SWIFT_OBJC_BRIDGING_HEADER = Runner/Runner-Bridging-Header.h
// (Flutter's default Runner already references a bridging header; merge these
//  imports into it if one already exists.)

#import "Security/tamper.h"
