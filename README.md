Skyld AV - on access virus scanner
==================================

Overview
--------

 Skyld AV provides on access virus scanning for Linux.

 The <a href="https://man7.org/linux/man-pages/man7/fanotify.7.html">fanotify</a>
 API is used to control file access. This requires a kernel compiled with

 <pre>CONFIG\_FANOTIFY=y
CONFIG\_FANOTIFY\_ACCESS\_PERMISSIONS=y</pre>

 On Debian and Fedora you can check the configuration with

 <pre>grep CONFIG\_FANOTIFY /boot/config-$(uname -r)</pre>

 Kernel version 3.8.0 or newer is recommended. You can check the
 version you are using with</p><pre>uname -a</pre>

 <a href="http://www.clamav.net">ClamAV</a> is used for scanning.

Building from git repository
----------------------------

 Install build dependencies. For Debian use the following command
 <pre>sudo apt-get install git autoconf-archive autotools-dev pkg-config \
 libc6-dev libcanberra-dev libcap-dev libclamav-dev libgtk2.0-dev \
 libmount-dev libnotify-dev</pre>

 For Fedora use the following command
 <pre>sudo yum install git libtool gcc-c++ gtk2-devel libnotify-devel \
 clamav-devel libcanberra-devel autoconf-archive libmount-devel libcap-devel</pre>

 Clone the git repository.

 <pre>git clone https://github.com/xypron/skyldav.git skyldav</pre>

 Move to the source directory.

 <pre>cd skyldav/</pre>

 Update from git repository.
 <pre>git pull</pre>

 Create the configure script.

 <pre>autogen.sh</pre>

 Configure the package.

 <pre>./configure</pre>

 Build the package.

 <pre>make</pre>

 Test the package.

 <pre>make check</pre>

 Install the package.

 <pre>sudo make install</pre>

 In directory <em>examples</em> files are supplied which can be used to
 start Skyld AV as daemon on a Debian system. Copy these to /etc/init.d
 and /etc/default.

