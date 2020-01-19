
## exfat-tools ?
Exfat-tools is mkfs(format)/fsck(repair) implementation for exfat filesystem under GNU GPL version 2. This opensource project was created by Namjae Jeon as exfat is officially supported in Linux kernel.

## Maintainers

* Namjae Jeon <linkinjeon@gmail.com>
* Hyunchul Lee <hyc.lee@gmail.com>

## building exfat tools

Install preprequisite packages:
```
	For Ubuntu:
	sudo apt-get install autoconf libtool pkg-config
```

```
	For Fedora, RHEL:
	sudo yum install autoconf automake libtool
```

Build steps:
```
        cd into the exfat-tools directory
        ./autogen.sh
        ./configure
        make
        make install
```

## USING exFAT TOOLS
```
- mkfs.exfat:
	Build a exfat filesystem on a device or partition(e.g. /dev/hda1, dev/sda1).

Usage example:
	1. No option(default) : cluster size adjustment as per device size, quick format.
		mkfs.exfat /dev/sda1
	2. To change cluster size(KB) user want
		mkfs.exfat -c 128 /dev/sda1
	3. For full format(zero out)
		mkfs.exfat -f /dev/sda1

- fsck.exfat(Preparing):
	Check the consistency of your exfat filesystem and optinally repair a corrupted device formatted by exfat.
```
