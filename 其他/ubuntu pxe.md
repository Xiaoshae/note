# ubuntu pxe

boot.ipxe

```
#!ipxe

dhcp

set server-ip 10.33.1.1

set initrd http://${server-ip}/boot/initrd
set vmlinuz http://${server-ip}/boot/vmlinuz
set nfsroot ${server-ip}:/pxe/nfs/ubuntu24.04

set cloud-init-cfg http://${server-ip}/config

kernel ${vmlinuz}
initrd ${initrd}

imgargs vmlinuz \
	boot=casper \
	ip=dhcp \
	netboot=nfs \
	nfsroot=${nfsroot} \
	autoinstall \
	cloud-config-url=/dev/null \
	ds=nocloud-net;s=${cloud-init-cfg}

boot
```



user-data

```
#cloud-config
autoinstall:
  apt:
    disable_components: []
    fallback: offline-install
    geoip: true
    mirror-selection:
      primary:
      - country-mirror
      - arches: &id001
        - amd64
        - i386
        uri: http://archive.ubuntu.com/ubuntu/
      - arches: &id002
        - s390x
        - arm64
        - armhf
        - powerpc
        - ppc64el
        - riscv64
        uri: http://ports.ubuntu.com/ubuntu-ports
    preserve_sources_list: false
    security:
    - arches: *id001
      uri: http://security.ubuntu.com/ubuntu/
    - arches: *id002
      uri: http://ports.ubuntu.com/ubuntu-ports
  codecs:
    install: false
  drivers:
    install: false
  identity:
    hostname: linux-server
    password: $6$i07etO2zc4br0758$48sp7TekYwyvJJkTpxEQdKUT.xZm/AIHEuGhAo8ALYxoKjI6yM3qcfENPoptuPSo664BQ44vG8Ply101JZbDG/
    realname: linux-user
    username: linux-user
  kernel:
    package: linux-generic
  keyboard:
    layout: us
    toggle: null
    variant: ''
  locale: en_US.UTF-8
  network:
    ethernets:
      ens33:
        dhcp4: true
    version: 2
  oem:
    install: auto
  source:
    id: ubuntu-server
    search_drivers: false
  ssh:
    allow-pw: true
    authorized-keys: []
    install-server: true
  storage:
    config:
    - ptable: gpt
      path: /dev/sda
      wipe: superblock-recursive
      preserve: false
      name: ''
      grub_device: false
      id: disk-sda
      type: disk
    - device: disk-sda
      size: 1G
      wipe: superblock
      flag: boot
      number: 1
      preserve: false
      grub_device: true
      path: /dev/sda1
      id: partition-0
      type: partition
    - fstype: fat32
      volume: partition-0
      preserve: false
      id: format-0
      type: format
    - device: disk-sda
      size: 1G
      wipe: superblock
      number: 2
      preserve: false
      grub_device: false
      path: /dev/sda2
      id: partition-1
      type: partition
    - fstype: ext4
      volume: partition-1
      preserve: false
      id: format-1
      type: format
    - device: disk-sda
      size: -1
      wipe: superblock
      number: 3
      preserve: false
      grub_device: false
      path: /dev/sda3
      id: partition-2
      type: partition
    - name: vg0
      devices:
      - partition-2
      preserve: false
      id: lvm_volgroup-0
      type: lvm_volgroup
    - name: lv-root
      volgroup: lvm_volgroup-0
      size: 100%FREE
      wipe: superblock
      preserve: false
      path: /dev/vg0/lv-root
      id: lvm_partition-0
      type: lvm_partition
    - fstype: ext4
      volume: lvm_partition-0
      preserve: false
      id: format-2
      type: format
    - path: /
      device: format-2
      id: mount-2
      type: mount
    - path: /boot
      device: format-1
      id: mount-1
      type: mount
    - path: /boot/efi
      device: format-0
      id: mount-0
      type: mount
  updates: security
  version: 1
```

