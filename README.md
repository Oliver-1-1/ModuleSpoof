# Module Spoof

## 1.1 Introduction: 
So recently I thought of a way to spoof the location of a DLL. By doing this you could hide important information from an attacker.
And the only way they could find this DLL is by brute-forcing pages or by reversing the application.
This project spoofs the DLL location by trapping/ redirecting internal API calls to the spoofed location.
To explain this I made a picture: 

![overview: ](https://i.imgur.com/sXmry9E.png "overview: ")

So this shows that internal calls to functions like
GetModuleHandleW, GetModuleHandleExW, GetProcAddress and GetProcAddressForCaller will return the location of the spoofed location.
The outside will still have the illusion that the DLL is at the location that PEB->LDR->protected.dll reports. 

## 1.2 Technical details: 
To achieve this I found two alternatives. One way is to hook LoadLibrary and when LoadLibrary is called with the right name we manually map our DLL to another location.
This has its drawbacks since we need to make sure the internal application never has access to the non-spoofed DLL because it will crash the application.
Making sure the internal application does not have that access is difficult since there might be a lot of win32-API functions reporting the non-spoofed location. 

The other way I found is by a public repository[1]. To get more info on how this works I suggest reading the project's code.
From what I've heard there are anti-cheats using this solution to break attacker's programs.

## 1.3 Honeypot:
The non-spoofed DLL is also honeypotted to detect if anyone is trying to access the memory.
This is also displayed in the picture.
To demonstrate this functionality I recorded a video on accessing this DLL. 

[!["video"](https://img.youtube.com/vi/PL9dBUEDFas/0.jpg)](https://www.youtube.com/watch?v=PL9dBUEDFas)

The honeypot catches most attackers but can be easily avoided by checking if the pages are loaded in memory before reading.

## 1.4 Proof of concept:
I made a simple proof of concept for this idea which can be found here: https://github.com/Oliver-1-1/ModuleSpoof.
This is a C++ project that spoofs the location of protected.dll.
Protected.dll includes basic tests to showcase that it's working.
I also tested this on game DLLs but without success. The most likely reason why it fails is because the manual mapping is faulty or that I forgot to hook a function.
I might fix this in the future if I get motivated. 

## 1.5 References:
[1] = https://github.com/changeofpace/Self-Remapping-Code

[2] = https://github.com/Oliver-1-1/ModuleSpoof

Other sources are found in the code.
