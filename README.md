# OWASP MSTG Android CrackMe

[The OWASP MSTG Android CrackMe](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes) is a series of Android applications with hidden flags designed to develop Java and Native reverse engineering skills.

## Used FOSS Tools
The following walkthrough uses the below tools:
- [Jadx-Gui](https://github.com/skylot/jadx)
- [APKTool](https://ibotpeaches.github.io/Apktool/)
- [Ghidra](https://ghidra-sre.org/)

## Challenge One
**Objective:** A secret string is hidden somewhere in this app. Find a way to extract it.
**Techniques Used:** Smali Patching.

### Tamper-Detection
<img align="right" width="200" src="/assets/tamper-checks.jpg">
<br>

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


## Challenges 2 and 3
TBC
