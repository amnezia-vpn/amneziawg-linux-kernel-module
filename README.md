# AmneziaWG kernel module

## Table of contents

- [Installation](#installation)
  - [Ubuntu](#ubuntu)
  - [Debian](#debian)
  - [Linux Mint](#linux-mint)
  - [RHEL/CentOS/SUSE/Fedora Core](#rhelcentossusefedora-core)
- [Manual build](#manual-build)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Installation

### Ubuntu

Open `Terminal` and proceed with following instructions:

1. (Optionally) Upgrade your system to latest packages including latest available kernel by running `apt-get full-upgrade`.
After kernel upgrade reboot is required.
2. Ensure that you have source repositories configured for APT - run `vi /etc/apt/sources.list` and make sure that there is
at least one line starting with `deb-src` is present and uncommented.
3. Install pre-requisites - run `sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)`.
4. Run `sudo add-apt-repository ppa:amnezia/ppa`.
5. Finally execute `sudo apt-get install -y amneziawg`.

### Debian

Open `Terminal` and do next steps:

1. (Optionally) Upgrade your system to latest packages including latest available kernel by running `apt-get full-upgrade`.
   After kernel upgrade reboot is required.
2. Ensure that you have source repositories configured for APT - run `vi /etc/apt/sources.list` and make sure that there is
   at least one line starting with `deb-src` is present and uncommented.
3. Execute following commands:
```shell
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list
echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt-get install -y amneziawg
```

### Linux Mint

Open `Software Sources` and make sure that `Source code repositories` (under `Optional Sources`) are enabled.

Proceed to `PPAs` section and add `ppa:amnezia/ppa` PPA repository, after that save configuration and rebuild `apt` cache.

After that, open `Terminal` and run:

```shell
sudo apt-get install -y amneziawg
```

### RHEL/CentOS/SUSE/Fedora Core

*If you use release that doesn't have DKMS support out of the box, you may need to install [EPEL](https://docs.fedoraproject.org/en-US/epel/#_quickstart) first.*

Open `Terminal` and run:

```shell
sudo dnf copr enable amneziavpn/amneziawg
sudo dnf install amneziawg-dkms amneziawg-tools
```

Before installation it is strictly recommended to upgrade your system kernel to the latest available version and perform
the reboot afterwards.

## Manual build

You may need to install kernel headers and/or build essentials packages before running following steps.

1. In Terminal:
    ```shell
    git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
    cd amneziawg-linux-kernel-module/src
    ```

2. Now, if you run modern Linux with kernel version 5.6+, you need to download your kernel's source from anywhere possible
and link resulting tree to `kernel` symlink:
    
    ```shell
    ln -s /path/to/kernel/source kernel
    ```
    
    Please note to find and provide full kernel sourcetree, not only headers. **If you run on legacy kernel (<5.6), you do not need to perform this step.**

3. Now perform build and installation:
    ```shell
    make
    sudo make install
    ```
   
    Or on a capable system you may want to use DKMS for this:
    ```shell
    sudo make dkms-install
    sudo dkms add -m amneziawg -v 1.0.0
    sudo dkms build -m amneziawg -v 1.0.0
    sudo dkms install -m amneziawg -v 1.0.0
    ```

## Configuration

> [!IMPORTANT]
> Only Jc, Jmin & Jmax values can vary between Client and Server

- Jc — 1 ≤ Jc ≤ 128; recommended range is from 2 to 5 inclusive
- Jmin — Jmin < Jmax; recommended value is 10
- Jmax — Jmin < Jmax ≤ 1280; recommended value is 50
- S1 — S1 < 1280; S1 + 56 ≠ S2; recommended range is from 2 to 10 inclusive
- S2 — S2 < 1280; recommended range is from 2 to 10 inclusive
- H1/H2/H3/H4 — must be unique among each other; recommended range is from 5 to 2147483647 inclusive

## Troubleshooting

### Low space on `/tmp` filesystem

Most installation instructions above assumes that you have enough space in system's `/tmp` partition (as setup script needs 
to manipulate with kernel's sourcetree with is pretty huge).

If you can not afford enough space in your `/tmp`, you may override temporary dir by setting `AWG_TEMP_DIR` environment variable
before the installation:

```shell
export AWG_TEMP_DIR="/home/ubuntu/tmp"
```

This setting should persist for future and will not require repeating.

### Kernel sourcetree could not be found automatically

In some rare cases, setup script may not find your kernel's sourcetree automatically. You may find appropriate sources by yourself
then and link them to DKMS module sources, e.g.

```shell
ln -s /path/to/your/kernel/sources /usr/src/amneziawg-1.0.0/kernel
```

Reinstall the package thereafter and you should get everything working.

Should you upgrade your kernel in the future, please remember that you may also need refresh sourcetree and update symlinks.

## License

This project is released under the [GPLv2](COPYING).
