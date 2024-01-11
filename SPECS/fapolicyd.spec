%global selinuxtype targeted
%global moduletype contrib
%define semodule_version 0.6

Summary: Application Whitelisting Daemon
Name: fapolicyd
Version: 1.3.2
Release: 1%{?dist}
License: GPLv3+
URL: http://people.redhat.com/sgrubb/fapolicyd
Source0: https://people.redhat.com/sgrubb/fapolicyd/%{name}-%{version}.tar.gz
Source1: https://github.com/linux-application-whitelisting/%{name}-selinux/releases/download/v%{semodule_version}/%{name}-selinux-%{semodule_version}.tar.gz
BuildRequires: gcc
BuildRequires: kernel-headers
BuildRequires: autoconf automake make gcc libtool
BuildRequires: systemd-devel openssl-devel rpm-devel file-devel file
BuildRequires: libcap-ng-devel libseccomp-devel lmdb-devel
BuildRequires: python3-devel
BuildRequires: python2-devel
BuildRequires: uthash-devel
Requires: rpm-plugin-fapolicyd >= 4.14.3-12
Recommends: %{name}-selinux
Requires(pre): shadow-utils
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

# we are making the dnf-plugin completelly dummy because of
# https://bugzilla.redhat.com/show_bug.cgi?id=1929163
# we require the rpm-plugin from now on and the dnf-plugin still needs to be part of
# the fapolicyd package because it provides safe upgrade path
Patch1: fapolicyd-dnf-plugin.patch
Patch2: selinux.patch
Patch3: fapolicyd-selinux-links.patch
Patch4: fapolicyd-leaks.patch
Patch5: fapolicyd-librpm-workaround.patch

%description
Fapolicyd (File Access Policy Daemon) implements application whitelisting
to decide file access rights. Applications that are known via a reputation
source are allowed access while unknown applications are not. The daemon
makes use of the kernel's fanotify interface to determine file access rights.

%package        selinux
Summary:        Fapolicyd selinux
Group:          Applications/System
Requires:       %{name} = %{version}-%{release}
BuildRequires:  selinux-policy
BuildRequires:  selinux-policy-devel
BuildArch: noarch
%{?selinux_requires}

%description    selinux
The %{name}-selinux package contains selinux policy for the %{name} daemon.

%prep

%setup -q

# selinux
%setup -q -D -T -a 1

%patch -P 1 -p1 -b .dnf-plugin
%patch -P 2 -p1 -b .selinux
%patch -P 3 -p1 -b .selinux-links
%patch -P 4 -p1 -b .leaks
%patch -P 5 -p1 -b .librpm-workaround

# generate rules for python
sed -i "s|%python2_path%|`readlink -f %{__python2}`|g" rules.d/*.rules
sed -i "s|%python3_path%|`readlink -f %{__python3}`|g" rules.d/*.rules

interpret=`readelf -e /usr/bin/bash \
                   | grep Requesting \
                   | sed 's/.$//' \
                   | rev | cut -d" " -f1 \
                   | rev`

sed -i "s|%ld_so_path%|`realpath $interpret`|g" rules.d/*.rules

%build
cp INSTALL INSTALL.tmp
./autogen.sh
%configure \
    --with-audit \
    --with-rpm \
    --disable-shared

%make_build

# selinux
pushd %{name}-selinux-%{semodule_version}
make
popd

%check
make check

# Selinux
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%install
%make_install
mkdir -p %{buildroot}/%{python3_sitelib}/dnf-plugins/
install -p -m 644 dnf/%{name}-dnf-plugin.py %{buildroot}/%{python3_sitelib}/dnf-plugins/
install -p -m 644 -D init/%{name}-tmpfiles.conf %{buildroot}/%{_tmpfilesdir}/%{name}.conf
mkdir -p %{buildroot}/%{_localstatedir}/lib/%{name}
mkdir -p %{buildroot}/run/%{name}
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/trust.d
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/rules.d
# get list of file names between known-libs and restrictive from sample-rules/README-rules
cat %{buildroot}/%{_datadir}/%{name}/sample-rules/README-rules \
  | grep -A 100 'known-libs' \
  | grep -B 100 'restrictive' \
  | grep '^[0-9]' > %{buildroot}/%{_datadir}/%{name}/default-ruleset.known-libs
chmod 644 %{buildroot}/%{_datadir}/%{name}/default-ruleset.known-libs

# selinux
install -d %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}
install -m 0644 %{name}-selinux-%{semodule_version}/%{name}.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}
install -d -p %{buildroot}%{_datadir}/selinux/devel/include/%{moduletype}
install -p -m 644 %{name}-selinux-%{semodule_version}/%{name}.if %{buildroot}%{_datadir}/selinux/devel/include/%{moduletype}/ipp-%{name}.if

#cleanup
find %{buildroot} \( -name '*.la' -o -name '*.a' \) -delete

%define manage_default_rules   default_changed=0 \
  # check changed fapolicyd.rules \
  if [ -e %{_sysconfdir}/%{name}/%{name}.rules ]; then \
    diff %{_sysconfdir}/%{name}/%{name}.rules %{_datadir}/%{name}/%{name}.rules.known-libs >/dev/null 2>&1 || { \
      default_changed=1; \
      #echo "change detected in fapolicyd.rules"; \
      } \
  fi \
  if [ -e %{_sysconfdir}/%{name}/rules.d ]; then \
    default_ruleset='' \
    # get listing of default rule files in known-libs \
    [ -e %{_datadir}/%{name}/default-ruleset.known-libs ] && default_ruleset=`cat %{_datadir}/%{name}/default-ruleset.known-libs` \
    # check for removed or added files \
    default_count=`echo "$default_ruleset" | wc -l` \
    current_count=`ls -1 %{_sysconfdir}/%{name}/rules.d/*.rules | wc -l` \
    [ $default_count -eq $current_count ] || { \
      default_changed=1; \
      #echo "change detected in number of rule files d:$default_count vs c:$current_count"; \
      } \
    for file in %{_sysconfdir}/%{name}/rules.d/*.rules; do \
      if echo "$default_ruleset" | grep -q "`basename $file`"; then \
        # compare content of the rule files \
        diff $file %{_datadir}/%{name}/sample-rules/`basename $file` >/dev/null 2>&1 || { \
          default_changed=1; \
          #echo "change detected in `basename $file`"; \
          } \
      else \
        # added file detected \
        default_changed=1 \
        #echo "change detected in added rules file `basename $file`"; \
      fi \
    done \
  fi \
  # remove files if no change against default rules detected \
  [ $default_changed -eq 0 ] && rm -rf %{_sysconfdir}/%{name}/%{name}.rules %{_sysconfdir}/%{name}/rules.d/* || : \


%pre
getent passwd %{name} >/dev/null || useradd -r -M -d %{_localstatedir}/lib/%{name} -s /sbin/nologin -c "Application Whitelisting Daemon" %{name}
if [ $1 -eq 2 ]; then
# detect changed default rules in case of upgrade
%manage_default_rules
fi

%post
# if no pre-existing rule file
if [ ! -e %{_sysconfdir}/%{name}/%{name}.rules ] ; then
 files=`ls %{_sysconfdir}/%{name}/rules.d/ 2>/dev/null | wc -w`
 # Only if no pre-existing component rules
 if [ "$files" -eq 0 ] ; then
  ## Install the known libs policy
  for rulesfile in `cat %{_datadir}/%{name}/default-ruleset.known-libs`; do
    cp %{_datadir}/%{name}/sample-rules/$rulesfile  %{_sysconfdir}/%{name}/rules.d/
  done
  chgrp %{name} %{_sysconfdir}/%{name}/rules.d/*
  if [ -x /usr/sbin/restorecon ] ; then
   # restore correct label
   /usr/sbin/restorecon -F %{_sysconfdir}/%{name}/rules.d/*
  fi
  fagenrules >/dev/null
 fi
fi
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service
if [ $1 -eq 0 ]; then
# detect changed default rules in case of uninstall
%manage_default_rules
else
  [ -e %{_sysconfdir}/%{name}/%{name}.rules ] && rm -rf %{_sysconfdir}/%{name}/rules.d/* || :
fi

%postun
%systemd_postun_with_restart %{name}.service

%files
%doc README.md
%{!?_licensedir:%global license %%doc}
%license COPYING
%attr(755,root,%{name}) %dir %{_datadir}/%{name}
%attr(755,root,%{name}) %dir %{_datadir}/%{name}/sample-rules
%attr(644,root,%{name}) %{_datadir}/%{name}/default-ruleset.known-libs
%attr(644,root,%{name}) %{_datadir}/%{name}/sample-rules/*
%attr(644,root,%{name}) %{_datadir}/%{name}/fapolicyd-magic.mgc
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}/trust.d
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}/rules.d
%attr(644,root,root) %{_sysconfdir}/bash_completion.d/*
%ghost %verify(not md5 size mtime) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/rules.d/*
%ghost %verify(not md5 size mtime) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.rules
%ghost %verify(not md5 size mtime) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/compiled.rules
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}-filter.conf
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.trust
%attr(644,root,root) %{_unitdir}/%{name}.service
%attr(644,root,root) %{_tmpfilesdir}/%{name}.conf
%attr(755,root,root) %{_sbindir}/%{name}
%attr(755,root,root) %{_sbindir}/%{name}-cli
%attr(755,root,root) %{_sbindir}/fagenrules
%attr(644,root,root) %{_mandir}/man8/*
%attr(644,root,root) %{_mandir}/man5/*
%ghost %attr(440,%{name},%{name}) %verify(not md5 size mtime) %{_localstatedir}/log/%{name}-access.log
%attr(770,root,%{name}) %dir %{_localstatedir}/lib/%{name}
%attr(770,root,%{name}) %dir /run/%{name}
%ghost %attr(660,root,%{name}) /run/%{name}/%{name}.fifo
%ghost %attr(660,%{name},%{name}) %verify(not md5 size mtime) %{_localstatedir}/lib/%{name}/data.mdb
%ghost %attr(660,%{name},%{name}) %verify(not md5 size mtime) %{_localstatedir}/lib/%{name}/lock.mdb
%{python3_sitelib}/dnf-plugins/%{name}-dnf-plugin.py
%{python3_sitelib}/dnf-plugins/__pycache__/%{name}-dnf-plugin.*.pyc

# selinux
%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{name}
%{_datadir}/selinux/devel/include/%{moduletype}/ipp-%{name}.if

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{name}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%changelog
* Wed Jul 19 2023 Radovan Sroka <rsroka@redhat.com> - 1.3.2-1
RHEL 8.9.0 ERRATUM
- Rebase fapolicyd to the latest stable version
Resolves: RHEL-519
- RFE: send rule number to fanotify so it gets audited
Resolves: RHEL-628
- Default q_size doesn't match manpage's one
Resolves: RHEL-629
- fapolicyd can leak FDs and never answer request, causing target process to hang forever
Resolves: RHEL-632
- fapolicyd needs to make sure the FD limit is never reached
Resolves: RHEL-631
- fapolicyd still allows execution of a program after "untrusting" it
Resolves: RHEL-630
- Fix broken backwards compatibility backend numbers
Resolves: RHEL-731
- fapolicyd can create RPM DB files /var/lib/rpm/__db.xxx with bad ownership causing AVCs to occur
Resolves: RHEL-829
- SELinux prevents the fapolicyd from reading symlink (cert_t)
Resolves: RHEL-820

* Mon Jan 30 2023 Radovan Sroka <rsroka@redhat.com> - 1.1.3-12
RHEL 8.8.0 ERRATUM
- statically linked app can execute untrusted app
Resolves: rhbz#2088349
- Starting manually fapolicyd while the service is already running breaks the system
Resolves: rhbz#2103352
- Cannot execute /usr/libexec/grepconf.sh when falcon-sensor is enabled
Resolves: rhbz#2087040
- fapolicyd: Introduce filtering of rpmdb
Resolves: rhbz#2165645

* Fri Aug 05 2022 Radovan Sroka <rsroka@redhat.com> - 1.1.3-8
RHEL 8.7.0 ERRATUM
- rebase fapolicyd to the latest stable vesion
Resolves: rhbz#2100087
- fapolicyd does not correctly handle SIGHUP
Resolves: rhbz#2070639
- fapolicyd often breaks package updates
Resolves: rhbz#2111243
- drop libgcrypt in favour of openssl
Resolves: rhbz#2111935
- fapolicyd.rules doesn't advertise that using a username/groupname instead of uid/gid also works
Resolves: rhbz#2103914
- fapolicyd gets way too easily killed by OOM killer
Resolves: rhbz#2100089
- compiled.rules file ownership and mode
Resolves: rhbz#2066653
- Faulty handling of static applications
Resolves: rhbz#2084497
- Introduce ppid rule attribute
Resolves: rhbz#2102563
- CVE-2022-1117 fapolicyd: fapolicyd wrongly prepares ld.so path [rhel-8.7.0]
Resolves: rhbz#2069121
- Fapolicyd denies access to /usr/lib64/ld-2.28.so [rhel-8.7.0]
Resolves: rhbz#2068105

* Wed Feb 16 2022 Radovan Sroka <rsroka@redhat.com> - 1.1-1
RHEL 8.6.0 ERRATUM
- rebase to 1.1
Resolves: rhbz#1939379
- introduce rules.d feature
Resolves: rhbz#2054741
- remove pretrans scriptlet
Resolves: rhbz#2051485

* Mon Dec 13 2021 Zoltan Fridrich <zfridric@redhat.com> - 1.0.4-2
RHEL 8.6.0 ERRATUM
- rebase to 1.0.4
- added rpm_sha256_only option
- added trust.d directory
- allow file names with whitespace in trust files
- use full paths in trust files
Resolves: rhbz#1939379
- fix libc.so getting identified as application/x-executable
Resolves: rhbz#1989272
- fix fapolicyd-dnf-plugin reporting as '<invalid>'
Resolves: rhbz#1997414
- fix selinux DSP module definition in spec file
Resolves: rhbz#2014445

* Thu Aug 19 2021 Radovan Sroka <rsroka@redhat.com> - 1.0.2-7
- fapolicyd abnormally exits by executing sosreport
- fixed multiple problems with unlink()
- fapolicyd breaks system upgrade, leaving system in dead state - complete fix
Resolves: rhbz#1943251

* Tue Feb 16 2021 Radovan Sroka <rsroka@redhat.com> - 1.0.2-3
RHEL 8.4.0 ERRATUM
- rebase to 1.0.2
- strong dependency on rpm/rpm-plugin-fapolicyd
- installed dnf-plugin is dummy and we are not using it anymore
- enabled integrity setting
Resolves: rhbz#1887451
- added make check
- Adding DISA STIG during OS installation causes 'ipa-server-install' to fail
- fixed java detection
Resolves: rhbz#1895435
- dnf update fails when fapolicyd is enabled
Resolves: rhbz#1876975
- fapolicyd breaks system upgrade, leaving system in dead state - complete fix
Resolves: rhbz#1896875

* Tue Jun 30 2020 Radovan Sroka <rsroka@redhat.com> - 1.0-3
RHEL 8.3 ERRATUM
- fixed manpage fapolicyd-conf
Resolves: rhbz#1817413

* Mon May 25 2020 Radovan Sroka <rsroka@redhat.com> - 1.0-2
RHEL 8.3 ERRATUM
- rebase to v1.0
- installed multiple policies to /usr/share/fapolicyd
  - known-libs (default)
  - restrictive
- installed fapolicyd.trust file
- enhanced fapolicyd-cli
Resolves: rhbz#1817413
- introduced fapolicyd-selinux that provides SELinux policy module
Resolves: rhbz#1714529

* Tue Mar 03 2020 Radovan Sroka <rsroka@redhat.com> - 0.9.1-4
RHEL 8.2 ERRATUM
- fixed possible heap buffer overflow in elf parser
Resolves: rhbz#1807912

* Tue Feb 11 2020 Radovan Sroka <rsroka@redhat.com> - 0.9.1-3
RHEL 8.2 ERRATUM
- fixed build time python interpreter detection (spec)
- added python2-devel as a BuildRequires (spec)
- allow running bash scripts in home directories
Resolves: rhbz#1801872

* Wed Nov 20 2019 Radovan Sroka <rsroka@redhat.com> - 0.9.1-2
RHEL 8.2 ERRATUM
- rebase to v0.9.1
- updated default configuration with new syntax
- removed daemon mounts configuration
Resolves: rhbz#1759895
- default fapolicyd policy prevents Ansible from running
- added ansible rule to default ruleset
Resolves: rhbz#1746464
- suspicious logs on service start
Resolves: rhbz#1747494
- fapolicyd blocks dracut from generating initramfs
- added dracut rule to default configuration
Resolves: rhbz#1757736
- fapolicyd fails to identify perl interpreter
Resolves: rhbz#1765039

* Wed Jul 24 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.10-3
- added missing manpage for fapolicyd-cli
Resolves: rhbz#1708015

* Mon Jul 22 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.10-2
- Convert hashes to lowercase like sha256sum outputs
- Stop littering STDOUT output for dnf plugin in fapolicyd
Resolves: rhbz#1721496

* Tue Jun 18 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.10-1
- new upstream release
Resolves: rhbz#1673323

* Mon May 06 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.9-1
- New upstream release
- imported from fedora30
  resolves: rhbz#1673323

* Wed Mar 13 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.8-2
- backport some patches to resolve dac_override for fapolicyd

* Mon Mar 11 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.8-1
- New upstream release
- Added new DNF plugin that can update the trust database when rpms are installed
- Added support for FAN_OPEN_EXEC_PERM

* Thu Jan 31 2019 Fedora Release Engineering <releng@fedoraproject.org> - 0.8.7-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild


* Wed Oct 03 2018 Steve Grubb <sgrubb@redhat.com> 0.8.7-1
- New upstream bugfix release

* Fri Jul 13 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.8.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Thu Jun 07 2018 Steve Grubb <sgrubb@redhat.com> 0.8.6-1
- New upstream feature release

* Fri May 18 2018 Steve Grubb <sgrubb@redhat.com> 0.8.5-2
- Add dist tag (#1579362)

* Fri Feb 16 2018 Steve Grubb <sgrubb@redhat.com> 0.8.5-1
- New release
