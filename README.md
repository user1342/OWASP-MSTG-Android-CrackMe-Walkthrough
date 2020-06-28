# OWASP MSTG Android CrackMe Walkthrough

[The OWASP MSTG Android CrackMe](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes) is a series of Android applications with hidden flags designed to develop Java and Native reverse engineering skills.

## Used FOSS Tools
The following walkthrough uses the below tools:
- [Jadx-Gui](https://github.com/skylot/jadx)
- [APKTool](https://ibotpeaches.github.io/Apktool/)
- [Ghidra](https://ghidra-sre.org/)

## Challenge One
- **Objective:** A secret string is hidden somewhere in this app. Find a way to extract it.
- **Techniques Used:** Smali Patching.

### Tamper-Detection
<img align="right" width="200" src="/assets/tamper-checks.jpg">

One mechanism that all three of the CrackMe challenges have in common is Tamper Detection. In the case of the first app this is done by checking if the device is rooted or running as debuggable. There are a few ways that one could get around these checks. One method is by patching the apk to remove the pieces of code that orchestrate the tamper detection checks.  

To do this APKtool can be used to disassemble the application to a human readable form (In this case Smali).

```shell
apktool d UnCrackable-Level1.apk
```

Once completed traverse to the entry point of the application. In this case it is: ```sg/vantagepoint/uncrackable1/MainActivity```. Inside of the Main Activity the method that orchestrates the tamper-detection checks is the ```a``` method. By opening the application in Jadx-Gui the same method can be seen in Java (*Psudo code*).

```java
private void a(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() {
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}
```

After disassembling the apk, with APKtool, we can now view the code in Smali. This means that it can be patched and reassembled. This is what we'll do here and remove all of the non-necessary code in this method, leaving it to look like the below:

```smali
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-static {}, Lsg/vantagepoint/a/c;->a()Z

    move-result v0

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    const/high16 p1, 0x7f030000

    invoke-virtual {p0, p1}, Lsg/vantagepoint/uncrackable1/MainActivity;->setContentView(I)V

    return-void
.end method
```

At this stage when the application launches there will be no pop-ups or tamper detection checks. For reference the method ```a``` still exists in the code base, however, it is no longer referenced.

### Finding The Key
Reviewing the Java code in Jadx-Gui and viewing the method ```a``` in ```sg/vantagepoint/uncrackable1/a``` we can see the Java method that is called to identify if the correct key has been entered into the application.

```java
public static boolean a(String str) {
    byte[] bArr;
    byte[] bArr2 = new byte[0];
    try {
        bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
        bArr = bArr2;
    }
    return str.equals(new String(bArr));
}
```

Here it can be seen that the inputted string represented by ```str``` is being compared against the valid string represented as the byte array ```bArr```. That being the case if we were to have access to this byte array after it was converted to a string we would be able to identify the correct key.

Continuing with the patching approach, this ```a``` method can also be patched, however, instead of removing code this time a log statement will be added.

Opening this method's Smali file and going to the line just before the ```return``` in the ```a``` method the below Smali can be added:

```smali
const-string v7, "log-tag"

invoke-static {v7, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

In addition to this alter the locals variable at the top of the method to the below:

```smali
.locals 8
```

Prior to our new log statement the key is set to the ```v1``` register. The log statement then logs this.

Adding this code means that when the ```verify``` button is selected it will log to logcat the key. View this with the following ```adb``` command:

```shell
adb logcat -s "log-tag"
```

In addition to this if you wanted to change the application to always display that the key was valid, even when it wasn't, you can replace the return statement at the end of the ```a``` method with the below lines:

```smali
const v1, true
return v1
```

**Key**: ```I want to believe```


## Challenges 2
- **Objective:** A secret string is hidden somewhere in this app. Find a way to extract it.
- **Techniques Used:** Smali and ARM Patching and gdb debugging.

A large part of the completion of this challenge was inspired by the writeup on the challenge by [sh3llc0d3r](http://sh3llc0d3r.com/owasp-uncrackable-android-level2).  

### Setting up the device
**Tl;Dr**: The target device should be running ARMv8, have a read/ write ```/system``` mount, and be rooted.

In this challenge I'll be patching the ARMv8 ELF library and remotely attaching a ```gdb``` instance to it. Because of this we'll need to use an ARMv8 device that is both rooted and is able to have the ```/system``` partition re-mounted to read/write. For this I'll be using a Android emulator running API level 25 (Nougat), without Google Play Services, running on ARM64-v8a. In later versions of Android Studio you may have problems running such an emulator, if you do try downgrading your version of the emulator with the below versions - as described in these posts ([Stack Overflow](https://stackoverflow.com/questions/49120854/how-to-downgrade-android-emulator/49284378#49284378) and [Stack Exchange](https://android.stackexchange.com/questions/212001/armv8-image-stuck-on-booting-process)).
- http://dl.google.com/android/repository/emulator-darwin-4266726.zip
- http://dl.google.com/android/repository/emulator-windows-4266726.zip
- http://dl.google.com/android/repository/emulator-linux-4266726.zip

Later in the challenge I will be remounting the ```/system``` mount on the device. By default this isn't possible on [some versions of Android](https://stackoverflow.com/questions/36670592/cannot-change-android-system-directory-to-rw). To get around this traverse to your Android SDK location (Commonly at ```AppData\Local\Android\Sdk```) and inside of the ```tools``` directory run the following command to list your emulators: ```.\emulator.exe -list-avds```. Once you have the name of your ARMv8 emulator run it with the following command: ```.\emulator.exe -writable-system -netdelay none -netspeed full -avd <emulator_name>```.

### Java Tamper-detection
Similar to Challenge One the application for Challenge Two has similar tamper detection checks, where they are checking if the device is rooted or if the application is running as debuggable. To overcome this we can use the same technique as in Challenge One.

Use APKTool on the application to disassemble the Dalvik assembly to human readable Smali. The ```-r``` parameter instructs APKtool to not unpack the applications resources. We're doing this as we won't be needing them and not doing this can sometimes lead to problems when reconstructing the APK.

```shell
apktool d UnCrackable-Level2.apk -r
```

Traverse to the directory created by APKTool and then go to the entry point of the application at ```smali\sg\vantagepoint\uncrackable2\MainActivity.smali```. As a comparison we can also open the application in Jadx-gui to compare the Smali with the decompiled Java equivalent.

This ```onCreate``` method is shown below:

```java
public void onCreate(Bundle bundle) {
       init();
       if (b.a() || b.b() || b.c()) {
           a("Root detected!");
       }
       if (a.a(getApplicationContext())) {
           a("App is debuggable!");
       }
       new AsyncTask<Void, String, String>() {
           /* access modifiers changed from: protected */
           /* renamed from: a */
           public String doInBackground(Void... voidArr) {
               while (!Debug.isDebuggerConnected()) {
                   SystemClock.sleep(100);
               }
               return null;
           }

           public void onPostExecute(String str) {
               MainActivity.this.a("Debugger detected!");
           }
       }.execute(new Void[]{null, null, null});
       this.m = new CodeCheck();
       super.onCreate(bundle);
       setContentView((int) R.layout.activity_main);
   }
```

In the Smali we are going to remove all unnecessary code in the ```onCreate``` method so that it looks like the below. This has removed the conditions and checks that perform the tamper detection.

```smali
# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4

    invoke-direct {p0}, Lsg/vantagepoint/uncrackable2/MainActivity;->init()V

    invoke-static {}, Lsg/vantagepoint/a/b;->a()Z

    move-result v0

    new-instance v0, Lsg/vantagepoint/uncrackable2/CodeCheck;

    invoke-direct {v0}, Lsg/vantagepoint/uncrackable2/CodeCheck;-><init>()V

    iput-object v0, p0, Lsg/vantagepoint/uncrackable2/MainActivity;->m:Lsg/vantagepoint/uncrackable2/CodeCheck;

    invoke-super {p0, p1}, Landroid/support/v7/app/c;->onCreate(Landroid/os/Bundle;)V

    const p1, 0x7f09001b

    invoke-virtual {p0, p1}, Lsg/vantagepoint/uncrackable2/MainActivity;->setContentView(I)V

    return-void
.end method

```

This Smali means that from the original method the only lines we are keeping are the below and we are removing the conditions and checks that performed the tamper detection.

```java
init();
this.m = new CodeCheck();
super.onCreate(bundle);
setContentView((int) R.layout.activity_main);
```

### ARM Tamper-detection checks
To complete this challenge we are going to be using ```gdb``` to connect to the challenge application's process. As described in the book [Learning Linux Binary Analysis](https://books.google.co.uk/books?id=42pLDAAAQBAJ&pg=PA89&lpg=PA89&dq=ptrace+the+process+may+already+be+being+traced&source=bl&ots=_wZQ93f9l1&sig=ACfU3U2gumv_9Yf-ZJFEIUU56OhcPPNWqA&hl=en&sa=X&ved=2ahUKEwiW0tu_3qTqAhXWEcAKHTaxDg4Q6AEwAHoECAkQAQ#v=onepage&q=ptrace%20the%20process%20may%20already%20be%20being%20traced&f=false) ```ptrace``` is commonly used as an anti-debugger technique. Here a process traces itself, and because a process can only have one tracer at a time it means that a reverse engineer would not be able to also trace the process. This is indeed what is happening in the challenge 2 application and so before we can use ```gdb``` we will need to get around this problem. The way that we'll do this is by patching it out of the application.

Opening the application in Jadx-gui and traversing to the entry point at ```sg.vantagepoint.uncrackable2.MainActivity.java```, as with the previous step, we can see the line:

```java
static {
    System.loadLibrary("foo");
}
```

This line indicates that a library is being loaded by the application and also that that library will be located in the applications ```/lib``` folder (```System.loadLibrary()``` always loads from ```/lib```, while ```System. load()``` loads from a given path). Following the code flow we can see that the ```CodeCheck``` class declares a native method called ```bar``` from this library. We can also see that it is this ```CodeCheck``` class that is used to verify the key input in this challenge. Below we can see this ```CodeCheck``` class.

```java
public class CodeCheck {
    private native boolean bar(byte[] bArr);

    public boolean a(String str) {
        return bar(str.getBytes());
    }
}
```

Returning to the disassembled apk that we created earlier with APKTool we can traverse to the ```/lib``` folder. As I'll be targeting ARMv8 I'm going to remove all sub-directories inside of this directory except for the ```arm64-v8a``` (This will then throw an error if installed on a non-ARM-v8 device). Now traversing to the ```arm64-v8a``` directory we can see the ```libfoo.so``` ELF binary.

After creating a new Ghidra project and importing this binary we're going to need to install a Ghidra extension. The Ghidra [Save Patch](https://github.com/schlafwandler/ghidra_SavePatch) extension allows for patching of ELF binaries which is not supported in base-Ghidra. After installing this script it can be enabled under: windows -> script manager -> filtering.

To patch an instruction (or series of instructions) right click on the instruction you want to patch and select ```Patch Instruction``` then change the instruction to the desired instruction. To save the patched ELF file select the changed instructions in the Listing view and run the script.

<br>
<p align="center">
  <img src="/assets/patchInstruction.png" width="500" />
  <img src="/assets/savePatchConfig.png" width="500" />
</p>
<br>

To remove the ```ptrace``` code we're going to replace several key instructions with ```nop``` instructions. The main instruction is the one below:

```
00100978 a6  ff  ff  97    bl         ptrace                                           long ptrace(__ptrace_request __r)
```
This is the instruction that calls the ```ptrace``` function and in C looks like the below:

```C
uVar2 = ptrace(PTRACE_ATTACH,(ulonglong)\__pid,0,0);
```

I also removed two following instructions relating to ```ptrace``` so that now the ARM code looks like the following:

```ARM
00100950 e1  03  1f  aa    mov        x1,xzr
00100954 e3  03  1f  aa    mov        x3,xzr
00100958 1f  20  03  d5    nop
0010095c 1d  00  00  14    b          LAB_001009d0
LAB_00100960                          XREF[1]:     00100940 (j)   
00100960 1f  20  03  d5    nop
00100964 f3  03  00  2a    mov        w19 ,w0
00100968 e0  03  1c  32    mov        w0,#0x10
0010096c e1  03  13  2a    mov        w1,w19
00100970 e2  03  1f  aa    mov        x2,xzr
00100974 e3  03  1f  aa    mov        x3,xzr
00100978 1f  20  03  d5    nop
```

At this stage select the changed instructions and run the Ghidra Save Patch script saving over the existing ```libfoo.so``` ELF binary. After both the SMALI and ARM have been patched we can reassemble the SMALI and bundle the APK. To do this run the following commands (Making sure that the Android Studio build tools are on your path):

```shell
apktool b UnCrackable-Level2
```

This should bundle the APK, after which traverse to ```UnCrackable-Level2/dist```.

```shell
keytool -genkey -v -keystore custom.keystore -alias mykeyaliasname -keyalg RSA -keysize 2048 -validity 10000
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore custom.keystore -storepass password *.apk mykeyaliasname
zipalign 4 UnCrackable-Level2.apk repackaged-final.apk
adb install repackaged-final.apk
```

### Debugging the apk with Gdb
Up until this point I've been using Windows to complete these challenges, however, at this point I've switched over the [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/learn/modules/get-started-with-windows-subsystem-for-linux/) which there are several [guides](https://docs.microsoft.com/en-us/learn/modules/get-started-with-windows-subsystem-for-linux/2-enable-and-install) on how to setup if you are doing similar. If needing to access files from the Ubuntu file system from Windows you can find them at ```AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs```.

As ```gdb``` does not come installed on all versions of Ubuntu you may need to install it with ```sudo apt-get install gdb```. As I am working on a different architecture to the Android emulator I instead had to install ```gdb-multiarch``` which is used when [debugging across architectures](https://stackoverflow.com/questions/53524546/gdbserver-target-description-specified-unknown-architecture-aarch64) and can be installed with ```sudo apt-get install gdb-multiarch```. When using this the command ```gdb-multiarch``` is used instead of ```gdb```.

On the Ubuntu CLI you will then need to download the Android NDK to get a copy of ```gdbserver```. To do this follow the below steps:
```shell
mkdir gdb
cd gdb
wget https://dl.google.com/android/repository/android-ndk-r21d-linux-x86_64.zip
sudo apt-get install unzip
unzip android-ndk-r21d-linux-x86_64.zip
adb push .\gdbserver /data/local/tmp
adb shell
```

Moving onto the device with the make sure to be root for the following commands (depending on your device setup this may differ, however, is commonly done with the ```su``` command.) [This guide](https://resources.infosecinstitute.com/android-hacking-and-security-part-20-debugging-apps-on-android-emulator-using-gdb/#gref) also shows how to setup gdb on an Android device.

First identify the system partition on the device. Do this by taking the directory returned from the following command (For me on this virtual device the directory was ```/dev/block/vda```). Take the output of that command and use it with the second command to set the mount as read/ write (rw). Finally move the ```gdbserver``` binary to the system directory.

```shell
mount | grep system
mount -o rw,remount /dev/block/vda /system
cp /data/local/tmp/gdbserver /system/bin/
```

Next make sure the challenge application is running and then run the following command to get the process id of the application (this will be the first number displayed). After this run ```gdbserver``` on the pid. If you receive an error at this stage that the process is already being traced then the patching of the ELF binary has not been successful.

```shell
ps | grep uncrackable
gdbserver64 :8888 --attach <process id>
```

After this point the application will become unresponsive (this is normal). Going back to our Ubuntu console forward the port ```8888``` from the device and remotely attach ```gdb``` (or ```gdb-multiarch``` in my case) to the process.

```
adb forward tcp:8888 tcp:8888
gdb-multiarch
```
In GDB:
```
target remote :8888
```
Briefly returning to the ELF binary in Ghidra we can see the following block of instructions:

```ARM
00100e50 e1  03  00  91    mov        x1,sp
00100e54 e2  02  80  52    mov        w2,#0x17
00100e58 e0  03  15  aa    mov        x0,x21
00100e5c 71  fe  ff  97    bl         strncmp int strncmp(char * __s1, char *
00100e60 60  01  00  34    cbz        w0,LAB_00100e8c

```
This translates to the following in C:

```
if ((iVar2 == 0x17) && (iVar2 = strncmp(__s1,(char *)&local_50,0x17), iVar2 == 0)) {
  uVar3 = 1;
}
```

This ```strncmp``` is comparing the value we enter into the application with a pre-configured value. As ```strncmp``` compares register 0 and 1 we can set a breakpoint at this ```strncmp``` and then view our registers to view the value being compared against (which is the enetered data and the challenge key).

As the instruction address we have in Ghidra is only an offset we will need to get the current address of this ```strncmp```. To do this we can run the following gdb command and find the ```strncmp``` instruction.

```shell
disass Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
```

In finding the ```strncmp``` instruction you should see something like the below:

```
0x0000007c6688ee4c <+160>:   b.ne    0x7c6688ee64 <Java_sg_vantagepoint_uncrackable2_CodeCheck_bar+184>
0x0000007c6688ee50 <+164>:   mov     x1, sp
0x0000007c6688ee54 <+168>:   mov     w2, #0x17
0x0000007c6688ee58 <+172>:   mov     x0, x21
0x0000007c6688ee5c <+176>:   bl      0x7c6688e820 <strncmp@plt>
```

Taking the address of the ```strncmp``` (in my case ```0x0000007c6688ee5c```) we need to set a breakpoint (```b```), and continue (```c```) running the application's process.

```shell
b *0x0000007c6688ee5c
c
```

Now it's time to enter some data into the application. There is a check in the code which doesn't run the specified function if the inputted data is anything other than 23 characters. You can enter 23 characters manually into the app or generate them with ```printf "%0.s1" {1..23}``` on the Ubuntu CLI. Once you've entered the data and clicked ```Verify``` you should see that the breakpoint has been hit. Once this occurs view the registers of the process in ```gdb```:
```
info registers
```
You should see something like the below with all of the registers.
```
x0             0x7c50519340     533923468096
x1             0x7fde3d0230     549189386800
...
```

Taking the addresses from the previous output and using the below commands we can see that in register 0 is the data we added (many 1's) and in register 1 is the data it's being compared with (the key).

```
x/s 0x7c50519340
x/s 0x7fde3d0230
```

**Key**: ```Thanks for all the fish```

## Challenge 3
TBC
