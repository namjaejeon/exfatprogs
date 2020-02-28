
## exfat-utils
exfat-utils is mkfs(format)/fsck(repair) implementation for exfat filesystem under GNU GPL version 2.

## Maintainers
* Namjae Jeon <linkinjeon@gmail.com>
* Hyunchul Lee <hyc.lee@gmail.com>

## Buidling exfat-utils
Install preprequisite packages:
```
	For Ubuntu:
	sudo apt-get install autoconf libtool pkg-config

	For Fedora, RHEL:
	sudo yum install autoconf automake libtool
```

Build steps:
```
        cd into the exfat-utils directory
        ./autogen.sh
        ./configure
        make
        make install
```

## Using exfat-utils
```
- mkfs.exfat:
	Build a exfat filesystem on a device or partition(e.g. /dev/hda1, dev/sda1).

Usage example:
	1. No option(default) : cluster size adjustment as per device size, quick format.
		mkfs.exfat /dev/sda1
	2. To change cluster size(KB or MB or Byte) user want
		mkfs.exfat -c 1048576 /dev/sda1
		mkfs.exfat -c 1024K /dev/sda1
		mkfs.exfat -c 1M /dev/sda1
	3. For full format(zero out)
		mkfs.exfat -f /dev/sda1
	4. For set volume label, use -l option with string user want.
		mkfs.exfat -l "my usb" /dev/sda1

- fsck.exfat:
	Check the consistency of your exfat filesystem and optinally repair a corrupted device formatted by exfat.

Usage example:
	1. check the consistency.
		fsck.exfat /dev/sda1
	2. repair and fix.(preparing)
```
