MobileInsight
==============

## Introduction

[MobileInsight](http://mobileinsight.net) enables below-IP, fine-grained mobile network analytics on end device. It is a cross-platform package for mobile network monitoring and analysis, originally developed by researchers at [UCLA Wireless Networking Group (WiNG)](http://metro.cs.ucla.edu) and Purdue Peng Group, licensed under Apache Licence 2.0.

MobileInsight provides low-level monitors for mobile network, and extensible event-driven analyzers for major cellular protocols, such as radio resource control (RRC), mobility management (EMM), and session management (ESM). You can also define your own analyzers for customized usage.

Using MobileInsight, users can declare a monitor to track the network status and call ananlyzer for online/offline analysis. See [overview](http://mobileinsight.net/developer-guide.html) on how this works, and [examples](http://mobileinsight.net/tutorials.html) on how to use it.


## Installation

Currently MobileInsight supports installation on macOS and Ubuntu/Debian systems. To install it on Windows, please use our all-in-one virtual machine from [`mobileinsight-dev`](https://github.com/mobile-insight/mobileinsight-dev).



First clone or download the git repository to user local folder.



Next, run installation script (but __do not__ execute with root priviledge!):

    ./install-macos.sh (macOS)
    ./install-ubuntu.sh (Ubuntu)

The install script will install MobileInsight package to your `PYTHONPATH`, install MobileInsight GUI to `/usr/local/bin/mi-gui`, and run an offline analysis example at the end.

> [!WARNING]
>
> Recent attempts with the [install-ubuntu.sh](install-ubuntu.sh) script have run into an issue with building Wireshark. Notably, the compiler throws an error for `wireshark-*/epan/epan.h`. The `<glib.h>` header, defined within the `extern "C"` block, has become incompatible with pure C-style. To fix this, move the `#include <glib.h>` line out of the `extern` block -- in fact, you should be able to move all the `#include`s out of it.
>
> Remove this warning if/when this change is fixed upstream.


## Dependencies

MobileInsight builds on top of `pyserial` and `crcmod`, which can be installed using `pip`:

    pip install pyserial
    pip install crcmod

The GUI of MobileInsight requires `matplotlib` and `wxPython`. `matplotlib` can be installed via `pip`:

    pip install matplotlib

`wxPython` can be installed using Homebrew (macOS) or apt-get (Ubuntu).

    brew install wxpython (macOS)
    apt-get install python-wxgtk3.0 (Ubuntu)


## Upgrade to New Version

Old version of `mobileInsight-core` may have installed Wireshark and Glib libraries under the `/usr/lib` folder. The installation script will auto handle the uninstallation of the old version. If you encounter issues, you may execute the uninstallation script manually to remove them. Please run the uninstallation script with __root__ priviledge to perform proper clean up.

    sudo ./uninstall.sh


## How to Contribute

We love pull requests and discussing novel ideas. You can open issues here to report bugs. Feel free to improve MobileInsight and become a collaborator if you are interested.

The following Slack group is used exclusively for discussions about developing the MobileInsight and its sister projects:

+ Email: support@mobileinsight.net

For other advanced topics, please refer to the wiki and the [MobileInsight website](http://mobileinsight.net).
