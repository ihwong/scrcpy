# heteroFLUID Desktop Proxy App

## Quickstart

### heteroFLUID Platform Configuration

 1. ARTPWriterForUDP ip.txt setting (nothing else is required)
 
### Guest Proxy App Configuration

### Build

 1. Install Android Studio
 2. Android Studio -> SDK Manager -> Install Level 29, 30
 3. Install build dependencies
 4. $ export ANDROID_HOME=~/Android/Sdk
 5. $ cd tcp
 6. $ meson x --buildtype release --strip -Db_lto=true
 7. $ ninja -Cx
 
### Run

 1. $ ./x/app/scrcpy
 
## TCP Proxy App Workflow

 1. heteroFLUID: UI Selection -> TCP wait open
 2. Run Proxy App
 3. Proxy App will connect to the TCP connection at port 5001
 4. Proxy App will send DisplayInfo to the heteroFLUID host
 5. Host will start TCP streaming
 6. Proxy App will receive packets and decode them to the video
 
## TCP Development Details

 1. Forked from the original scrcpy (https://github.com/Genymobile/scrcpy/tree/0e4a6f462bcc628af00896eea38aa883d68acc88)

## DUAL Dependencies

```
sudo apt install libavfilter-dev libavfilter-extra libavfilter-extra7
```
