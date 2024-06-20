%global debug_package %{nil}

Name:           amneziawg-dkms
Version:        1.0.20240213
Release:        1%{?dist}
Epoch:          1
URL:            https://www.wireguard.com/
Summary:        Fast, modern, secure VPN tunnel
License:        GPLv2
Group:          System Environment/Kernel
BuildArch:      noarch

Source0:        https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  kernel-devel
BuildRequires:  sed
BuildRequires:  make
BuildRequires:  bc

Provides:       kmod(amneziawg.ko) = %{epoch}:%{version}-%{release}
Requires:       dkms
Requires:       kernel-devel
Requires:       make
Requires:       bc
Requires:       yum-utils
Requires:       rpm-build

%description
WireGuard is a novel VPN that runs inside the Linux Kernel and uses
state-of-the-art cryptography (the "Noise" protocol). It aims to be
faster, simpler, leaner, and more useful than IPSec, while avoiding
the massive headache. It intends to be considerably more performant
than OpenVPN. WireGuard is designed as a general purpose VPN for
running on embedded interfaces and super computers alike, fit for
many different circumstances. It runs over UDP.

%prep
%autosetup -p1 -n amneziawg-linux-kernel-module-%{version}

# Fix the Makefile for CentOS7 since it ships coreutils from 2013.
sed -i 's/install .* -D -t\(.\+\) /mkdir -p \1 \&\& \0/' %{_builddir}/amneziawg-linux-kernel-module-%{version}/src/Makefile

# Set version in dkms.conf and Makefile
sed -i "s/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"%{version}\"/" %{_builddir}/amneziawg-linux-kernel-module-%{version}/src/dkms.conf
sed -i "s/^MAKE\[0\]=\"make -C \/var\/lib\/dkms\/amneziawg\/.*/MAKE[0]=\"make -C \/var\/lib\/dkms\/amneziawg\/%{version}\/build\"/" %{_builddir}/amneziawg-linux-kernel-module-%{version}/src/dkms.conf
sed -i "s/^WIREGUARD_VERSION = .*/WIREGUARD_VERSION = %{version}/" %{_builddir}/amneziawg-linux-kernel-module-%{version}/src/Makefile


%build

%install
mkdir -p %{buildroot}%{_usrsrc}/amneziawg-%{version}/
make DESTDIR=%{buildroot} DKMSDIR=%{_usrsrc}/amneziawg-%{version}/ \
    -C %{_builddir}/amneziawg-linux-kernel-module-%{version}/src dkms-install

%post
dkms add -m amneziawg -v %{version} -q --rpm_safe_upgrade || :
dkms build -m amneziawg -v %{version} -q || :
dkms install -m amneziawg -v %{version} -q --force || :
echo "amneziawg-dkms-%{version}-%{release}" > /var/lib/dkms/amneziawg/%{version}/version

%preun
# Check if we are running an upgrade
if [ $1 -ne 0 ]; then
  WG_VERSION=$(dkms status amneziawg|grep installed|sort -r -V|awk '{print $2}'|cut -f1 -d,)
  if [ "$WG_VERSION" != "%{version}" ] ; then

    true

  else

    exit 0

  fi
fi

# If we are not running an upgrade then remove everything!
WG_VERSION_FILE=$(cat /var/lib/dkms/amneziawg/%{version}/version)
WG_RPM_VERSION=amneziawg-dkms-%{version}-%{release}
if [ "$WG_RPM_VERSION" = "$WG_VERSION_FILE" ]; then

    dkms remove -m amneziawg -v %{version} -q --all --rpm_safe_upgrade || :

fi

exit 0

%files
%{_usrsrc}/amneziawg-%{version}

%changelog
* Thu Feb 1 2024 Yuri Egorov <ye@amnezia.org> - 1.0.20240201-1
- Update to 1.0.20240201

* Tue Jun 28 2022 Joe Doss <joe@solidadmin.com> - 1.0.20220627-1
- Update to 1.0.20220627

* Wed Dec 8 2021 Joe Doss <joe@solidadmin.com> - 1.0.20211208-1
- Update to 1.0.20211208

* Tue Jun 15 2021 Joe Doss <joe@solidadmin.com> - 1.0.20210606-2
- Fix building on CentOS Stream

* Mon Jun 7 2021 Joe Doss <joe@solidadmin.com> - 1.0.20210606-1
- Update to 1.0.20210606

* Wed Apr 28 2021 Joe Doss <joe@solidadmin.com> - 1.0.20210424-1
- Update to 1.0.20210424

* Mon Feb 22 2021 Joe Doss <joe@solidadmin.com> - 1.0.20210219-1
- Update to 1.0.20210219

* Tue Jan 26 2021 Joe Doss <joe@solidadmin.com> - 1.0.20210124-1
- Update to 1.0.20210124

* Mon Dec 21 2020 Joe Doss <joe@solidadmin.com> - 1.0.20201221-1
- Update to 1.0.20201221

* Thu Nov 12 2020 Joe Doss <joe@solidadmin.com> - 1.0.20201112-1
- Update to 1.0.20201112

* Tue Sep 8 2020 Joe Doss <joe@solidadmin.com> 1.0.20200908-1
- Update to 1.0.20200908

* Wed Jul 29 2020 Joe Doss <joe@solidadmin.com> 1.0.20200729-1
- Update to 1.0.20200729

* Mon Jul 13 2020 Joe Doss <joe@solidadmin.com> 1.0.20200712-1
- Update to 1.0.20200712

* Thu Jun 25 2020 Joe Doss <joe@solidadmin.com> 1.0.20200623-1
- Update to 1.0.20200623

* Thu Jun 11 2020 Joe Doss <joe@solidadmin.com> 1.0.20200611-1
- Update to 1.0.20200611

* Wed May 20 2020 Joe Doss <joe@solidadmin.com> 1.0.20200520-1
- Update to 1.0.20200520

* Wed May 06 2020 Joe Doss <joe@solidadmin.com> 1.0.20200506-1
- Update to 1.0.20200506

* Thu Apr 30 2020 Joe Doss <joe@solidadmin.com> - 1.0.20200429-1
- Update to 1.0.20200429

* Mon Apr 27 2020 Joe Doss <joe@solidadmin.com> - 1.0.20200426-1
- Update to 1.0.20200426

* Mon Apr 13 2020 Joe Doss <joe@solidadmin.com> - 1.0.20200313-1
- Update to 1.0.20200313

* Wed Apr 1 2020 Joe Doss <joe@solidadmin.com> - 1.0.20200401-1
- Update to 1.0.20200401

* Tue Mar 31 2020 Joe Doss <joe@solidadmin.com> - 1.0.20200330-1
- WireGuard 1.0.0 has been released for Linux 5.6 :)

* Thu Mar 19 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200318-1
- Remove patch: amneziawg-linux-compat-RHEL-0.0.20200215.patch

* Sat Feb 15 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200215-2
- Apply patch: https://git.zx2c4.com/amneziawg-linux-compat/patch/?id=27ce49e385a87cb784368a0995f8284fd6887d8c

* Fri Feb 14 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200215-1
- Update to 0.0.20200215

* Wed Feb 5 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200205-1
- Update to 0.0.20200205

* Tue Jan 28 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200128-1
- Update to 0.0.20200128

* Tue Jan 21 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200121-1
- Update to 0.0.20200121

* Mon Jan 6 2020 Joe Doss <joe@solidadmin.com> - 0.0.20200105-1
- Update to 0.0.20200105
- RPM spec updates

* Thu Dec 26 2019 Joe Doss <joe@solidadmin.com> - 0.0.20191226-1
- Split amneziawg-tools back out into it's own spec
- Switch to https://git.zx2c4.com/amneziawg-linux-compat repo
- Move back to amneziawg-dkms spec

* Thu Dec 19 2019 Joe Doss <joe@solidadmin.com> - 0.0.20191219-1
- Update to 0.0.20191219

* Thu Dec 12 2019 Joe Doss <joe@solidadmin.com> - 0.0.20191212-1
- Update to 0.0.20191212

* Thu Dec 05 2019 Joe Doss <joe@solidadmin.com> - 0.0.20191205-1
- Update to 0.0.20191205

* Wed Nov 27 2019 Joe Doss <joe@solidadmin.com> - 0.0.20191127-1
- Update to 0.0.20191127
- Add /var/lib/dkms/amneziawg/%{version}/version
- Merge amneziawg-tools.spec and amneziawg-dkms.spec
- Move %posttrans back to $post as it didn't fix the Error! Could not locate dkms.conf file issues.
- Add in logic for better uninstalls and upgrades

* Mon Oct 14 2019 Joe Doss <joe@solidadmin.com> - 0.0.20191012-1
- Update to 0.0.20191012

* Mon Sep 16 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190913-1
- Update to 0.0.20190913

* Mon Sep 9 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190905-1
- Update to 0.0.20190905

* Tue Jul 2 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190702-1
- Update to 0.0.20190702

* Sat Jun 1 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190601-1
- Update to 0.0.20190601

* Fri May 31 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190531-1
- Update to 0.0.20190531

* Sat Apr 6 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190406-1
- Update to 0.0.20190406

* Wed Feb 27 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190227-1
- Update to 0.0.20190227

* Wed Jan 30 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190123-2
- Move %post to %posttrans to fix upgrade Error! Could not locate dkms.conf file errors.

* Thu Jan 24 2019 Joe Doss <joe@solidadmin.com> - 0.0.20190123-1
- Update to 0.0.20190123

* Wed Dec 19 2018 Joe Doss <joe@solidadmin.com> - 0.0.20181218-1
- Update to 0.0.20181218

* Thu Nov 22 2018 Joe Doss <joe@solidadmin.com> - 0.0.20181119-1
- Update to 0.0.20181119

* Thu Nov 15 2018 Joe Doss <joe@solidadmin.com> - 0.0.20181115-1
- Update to 0.0.20181115

* Sun Oct 14 2018 Joe Doss <joe@solidadmin.com> - 0.0.20181018-1
- Update to 0.0.20181018

* Sun Oct 14 2018 Joe Doss <joe@solidadmin.com> - 0.0.20181007-2
- Add make as a dependency

* Sun Oct 7 2018 Joe Doss <joe@solidadmin.com> - 0.0.20181007-1
- Update to 0.0.20181007

* Tue Sep 25 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180925-1
- Update to 0.0.20180925

* Tue Sep 18 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180918-1
- Update to 0.0.20180918

* Mon Sep 10 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180910-1
- Update to 0.0.20180910

* Wed Sep 5 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180904-1
- Update to 0.0.20180904

* Thu Aug 9 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180809-1
- Update to 0.0.20180809

* Sun Aug 5 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180802-1
- Update to 0.0.20180802

* Tue Jul 31 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180731-1
- Update to 0.0.20180731
- Upstream kernel submission happend today!

* Wed Jul 18 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180718-1
- Update to 0.0.20180718

* Tue Jul 10 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180708-1
- Update to 0.0.20180708

* Fri Jun 29 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180625-1
- Update to 0.0.20180625

* Wed Jun 20 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180620-1
- Update to 0.0.20180620

* Wed Jun 13 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180613-1
- Update to 0.0.20180613

* Wed May 30 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180531-1
- Update to 0.0.20180531

* Wed May 23 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180524-1
- Update to 0.0.20180524
- Always exit zero on dkms remove in %preun

* Thu May 17 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180519-1
- Update to 0.0.20180519

* Sun May 13 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180513-1
- Update to 0.0.20180513
- Drop support for RHEL 7.4, moving on instead to RHEL 7.5

* Fri Apr 20 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180420-1
- Update to 0.0.20180420

* Sun Apr 15 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180413-1
- Update to 0.0.20180413

* Mon Mar 05 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180304-1
- Update to 0.0.20180304

* Mon Feb 19 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180218-1
- Update to 0.0.20180218

* Sun Feb 04 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180202-1
- Update to 0.0.20180202

* Thu Jan 18 2018 Joe Doss <joe@solidadmin.com> - 0.0.20180118-1
- Update to 0.0.20180118

* Thu Dec 21 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171221-1
- Update to 0.0.20171221

* Tue Dec 12 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171211-1
- Update to 0.0.20171211

* Mon Nov 27 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171127-1
- Update to 0.0.20171127

* Thu Nov 23 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171122-1
- Update to 0.0.20171122

* Sat Nov 11 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171111-1
- Update to 0.0.20171111

* Wed Nov 01 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171101-1
- Update to 0.0.20171101

* Thu Oct 26 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171017-1
- Update to 0.0.20171017

* Wed Oct 11 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171011-1
- Update to 0.0.20171011

* Fri Oct 6 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171005-1
- Update to 0.0.20171005
- Update RPM spec URL to www.wireguard.com

* Mon Oct 2 2017 Joe Doss <joe@solidadmin.com> - 0.0.20171001-1
- Update to 0.0.20171001

* Mon Sep 18 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170918-1
- Update to 0.0.20170918
- Drop support for RHEL 7.3, moving on instead to RHEL 7.4

* Thu Sep 7 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170907-1
- Update to 0.0.20170907

* Wed Aug 9 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170810-1
- Update to 0.0.20170810

* Mon Jul 31 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170726-1
- Update to 0.0.20170726

* Thu Jul 6 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170706-1
- Update to 0.0.20170706

* Fri Jun 30 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170629-2
- Remove elfutils-libelf-devel as a dependancy
- Add kernel-devel as a dependancy

* Thu Jun 29 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170629-1
- Update to 0.0.20170629
- Add elfutils-libelf-devel as a dependancy

* Tue Jun 13 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170613-1
- Update to 0.0.20170613

* Mon Jun 12 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170612-1
- Update to 0.0.20170612

* Wed May 31 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170531-1
- Update to 0.0.20170531

* Wed May 17 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170517-1
- Update to 0.0.20170517

* Mon Apr 24 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170421-1
- Update to 0.0.20170421

* Mon Apr 10 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170409-1
- Update to 0.0.20170409

* Fri Mar 24 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170324-1
- Update to 0.0.20170324

* Mon Mar 20 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170320.1-1
- Update to 0.0.20170320.1

* Thu Mar 2 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170223-1
- Update to 0.0.20170223

* Thu Feb 16 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170214-1
- Update to 0.0.20170214

* Thu Jan 5 2017 Joe Doss <joe@solidadmin.com> - 0.0.20170105-1
- Update to 0.0.20170105

* Mon Dec 19 2016 Jason A. Donenfeld <jason@zx2c4.com> - 0.0.20161218-1
- Spec adjustments

* Wed Aug 17 2016 Joe Doss <joe@solidadmin.com> - 0.0.20160808-2
- Spec adjustments

* Mon Aug 15 2016 Joe Doss <joe@solidadmin.com> - 0.0.20160808-2
- Initial WireGuard DKMS RPM
- Version 0.0.20160808