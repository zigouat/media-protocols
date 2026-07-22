# Media Protocols

Zig implementations of various protocols related to media processing and streaming.

The projects is structured into modules, each module is a separate library that can be used independently. The modules are:

* `rtp/rtcp` - implementation of the real-time transport protocol (RTP) and real-time transport control protocol (RTCP).
    
    The following RFCs are also implemented as part of the `rtp/rtcp` module:
    * [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP: A Transport Protocol for Real-Time Applications.
    * [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF).
    * [RFC 8285](https://datatracker.ietf.org/doc/html/rfc8285) - A General Mechanism for RTP Header Extensions.

* `srtp` - [SRTP (Secure Real-time Transport Protocol)](https://datatracker.ietf.org/doc/html/rfc3711) implementation of the secure real-time transport protocol based on RFC 3711.
* `sdp` - [SDP (Session Description Protocol)](https://datatracker.ietf.org/doc/html/rfc4566) implementation for describing multimedia sessions based on RFC 4566.
* `rtsp` - [RTSP (Real Time Streaming Protocol)](https://datatracker.ietf.org/doc/html/rfc2326) implementation for controlling streaming media servers based on RFC 2326.
* `stun` - [STUN (Session Traversal Utilities for NAT)](https://datatracker.ietf.org/doc/html/rfc8489) implementation for NAT traversal based on RFC 8489.
* `ice` - [ICE (Interactive Connectivity Establishment)](https://datatracker.ietf.org/doc/html/rfc8445) implementation of the interactive connectivity establishment (ICE) protocol for Network Address Translator (NAT) Traversal.

## Status

This repo is under active development, and the implementations are not yet complete. Breaking changes may occur frequently.

## Installation
Add `media_protocols` as a dependency in your `build.zig.zon` file:

```bash
zig fetch --save git+https://github.com/zigouat/media-protocols.git#v0.1.0
```

Then, in your `build.zig` file, add the following:

```zig
const media_protocols = b.dependecy("media_protocols", .{ .target = .target, .optimize = optimize });

/// You can all the whole module:
exe.root_module.addImport("media_protocols", media_protocols.module("protocols"));

/// Or you can import only the modules you need:
exe.root_module.addImport("rtp", media_protocols.module("rtp"));
exe.root_module.addImport("ice", media_protocols.module("ice"));
```
