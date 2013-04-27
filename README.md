Skyld AV - online virus scanner invocation
==========================================

 Skyld AV provides on access virus scanning for Linux.

 The <a href="http://www.xypron.de/projects/fanotify-manpages">fanotify</a>
 API is used to control file access. This requires a kernel compiled with

 <pre>CONFIG\_FANOTIFY=y
 CONFIGi\_FANOTIFY\_ACCESS\_PERMISSIONS=y</pre>

 On Debian and Fedora you can check the configuration with

 <pre>grep CONFIG\_FANOTIFY /boot/config-`uname -r`</pre>

 Kernel version 3.8.0 or newer is recommended. You can check the
 version you are using with</p><pre>uname -a</pre>

 <a href="http://www.clamav.net">ClamAV</a> is used for scanning.
