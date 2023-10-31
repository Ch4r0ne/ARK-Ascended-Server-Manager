# ARK-Ascended-Server-Manager
This PowerShell script provides a user-friendly GUI for managing ARK Survival Ascended Server:

1. Configuration: Users can set server parameters like installation path, map, server name, player limit, and more via the GUI. Configuration data is saved in a JSON file.
2. Installation: The script can install the ARK server using SteamCMD. It downloads and sets up the necessary files automatically.
3. Update: Users can update the server using SteamCMD, ensuring it's current with the latest patches and content.
4. Start Server: The script constructs command line arguments based on user configuration and launches the server.

This script simplifies the server management process, offering a streamlined interface for both novice and experienced users. Users can easily configure, install, update, and start ARK game servers without delving into complex command lines or configurations.

## Build for Windows Server 2022 / 2019

![ASA_Server_Manager_Preview.png](Preview/ASA_Server_Manager_Preview_1.png)

## Port forward Ports
- UDP 7777 
- TCP Port = 27015 (default)

## Known Issue:
I'm currently facing a persistent problem where the server isn't getting listed. I've been diligently working on resolving this, but unfortunately, a solution has eluded me thus far. The detailed discussion of the issue can be found at this link. https://github.com/Ch4r0ne/ARK-Ascended-Server-Manager/discussions/1

In the meantime, I recommend checking out a similar project (on Debian 12) by my colleagues at https://github.com/cdp1337/ARKSurvivalAscended-Linux.
If the installation process doesn't work for you, which happened in my case as well, you can attempt the workaround suggested in this comment. https://github.com/cdp1337/ARKSurvivalAscended-Linux/issues/1#issuecomment-1786189928
After following the installation guide, make sure to adjust the start parameters as described. Once you've updated the values, you can proceed to start the service.

I appreciate your patience as I work towards resolving this issue. If you have any insights or suggestions, please feel free to share. Your input is invaluable in resolving this matter effectively.

## 🔍 Found a Bug? Help Us Improve!
Hello developers and early adopters! Welcome to our app's preview release. 
Your feedback is crucial as we refine every detail. 
If you encounter any bugs or unexpected behavior, please report them on GitHub. 
Your reports guide us toward a seamless user experience. Thank you!
