# frida-scripts
[![](https://img.shields.io/github/stars/0xdea/frida-scripts.svg?style=flat&color=yellow)](https://github.com/0xdea/frida-scripts)
[![](https://img.shields.io/github/forks/0xdea/frida-scripts.svg?style=flat&color=green)](https://github.com/0xdea/frida-scripts)
[![](https://img.shields.io/github/watchers/0xdea/frida-scripts.svg?style=flat&color=red)](https://github.com/0xdea/frida-scripts)
[![](https://img.shields.io/badge/frida-17.3.2-lightcoral)](https://github.com/frida/frida)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)

> "Just because you're paranoid doesn't mean they aren't after you." 
>
> -- Joseph Heller, Catch-22

A collection of my Frida.re instrumentation scripts to facilitate reverse engineering of mobile apps and more.

Blog post:  
<https://web.archive.org/web/20200623001844/https://techblog.mediaservice.net/2017/09/tracing-arbitrary-methods-and-function-calls-on-android-and-ios/>

*Note: My old iOS and Android scripts might require some tweakings. For a well-maintained project that includes some of my Frida scripts, refer to: <https://github.com/federicodotta/Brida>*

## iOS
* [**raptor_frida_ios_trace.js**](https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_ios_trace.js). Full-featured ObjC and Module tracer for iOS.
* [**raptor_frida_ios_enum.js**](https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_ios_enum.js). Collection of functions to enumerate ObjC classes and methods.
* [**ios-snippets/**](https://github.com/0xdea/frida-scripts/tree/master/ios-snippets). Miscellaneous script snippets for iOS (tested with Frida before 17.0.0).

## Android
* [**raptor_frida_android_trace.js**](https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js). Full-featured Java and Module tracer for Android.
* [**raptor_frida_android_enum.js**](https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_enum.js). Collection of functions to enumerate Java classes and methods.
* [**android-snippets/**](https://github.com/0xdea/frida-scripts/tree/master/android-snippets). Miscellaneous script snippets for Android (tested with Frida before 17.0.0).

## Linux
* [**raptor_frida_linux_trace.js**](https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_linux_trace.js). Full-featured function call tracer for Linux.
* [**raptor_frida_linux_enum.js**](https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_linux_enum.js). Collection of functions to enumerate modules and functions in a binary.

## Windows
* *TODO*

## macOS
* *TODO*
