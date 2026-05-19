%global selinuxtype targeted
%global moduletype distributed
%define semodule_version 1.1

Summary: Application Whitelisting Daemon
Name: fapolicyd
Version: 1.4.3
Release: 3%{?dist}
License: GPL-3.0-or-later
URL: https://github.com/linux-application-whitelisting/fapolicyd
Source0: https://github.com/linux-application-whitelisting/fapolicyd/releases/download/v%{version}/fapolicyd-%{version}.tar.gz
Source1: https://github.com/linux-application-whitelisting/%{name}-selinux/releases/download/v%{semodule_version}/%{name}-selinux-%{semodule_version}.tar.gz
Source2: https://github.com/bachradsusi.gpg
Source3: fapolicyd.sysusers
Source10: https://github.com/linux-application-whitelisting/fapolicyd/releases/download/v%{version}/fapolicyd-%{version}.tar.gz.asc
Source11: https://github.com/linux-application-whitelisting/%{name}-selinux/releases/download/v%{semodule_version}/%{name}-selinux-%{semodule_version}.tar.gz.asc
# we bundle uthash for eln
Source20: https://github.com/troydhanson/uthash/archive/refs/tags/v2.3.0.tar.gz#/uthash-2.3.0.tar.gz

# https://github.com/linux-application-whitelisting/fapolicyd
# $ git format-patch -N v1.4.3
# https://github.com/linux-application-whitelisting/fapolicyd-selinux
# $ git format-patch -N --start-number 100 --src-prefix=a/fapolicyd-selinux-1.1/ --dst-prefix=b/fapolicyd-selinux-1.1/ v1.1
# $ for j in [0-9]*.patch; do printf "Patch: %s\n" $j; done
# Patch list start
Patch: 0002-If-less-than-16-chars-were-read-allow-shebang-test-c.patch
Patch: 0003-Fix-binary-path-of-rpm-loader.patch
Patch: 0004-Map-file-with-MAP_SHARED-instead-of-MAP_PRIVATE.patch
Patch: 0005-Fix-segfault-when-interrupting-fapolicyd-startup.patch
Patch: 0006-Potential-memory-leak-on-early-return-in-file_append.patch
Patch: 0007-whitespace-fix.patch
Patch: 0008-Fix-32-bit-ELF-dynamic-section-parsing.patch
# Patch list end

BuildRequires: gcc
BuildRequires: kernel-headers
BuildRequires: autoconf automake make gcc libtool
BuildRequires: systemd systemd-devel openssl-devel rpm-devel file-devel file
BuildRequires: libcap-ng-devel libseccomp-devel lmdb-devel
BuildRequires: python3-devel
%if 0%{?fedora} || 0%{?rhel} > 10
BuildRequires: gpgverify
%else
BuildRequires: gnupg
%endif

%if 0%{?rhel} == 0
BuildRequires: uthash-devel
%endif

Requires: rpm-plugin-fapolicyd
Recommends: %{name}-selinux
Requires(pre): shadow-utils
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
Fapolicyd (File Access Policy Daemon) implements application whitelisting
to decide file access rights. Applications that are known via a reputation
source are allowed access while unknown applications are not. The daemon
makes use of the kernel's fanotify interface to determine file access rights.

%package        selinux
Summary:        Fapolicyd selinux
Group:          Applications/System
Requires:       %{name} = %{version}-%{release}
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
BuildRequires:  selinux-policy-devel
BuildArch: noarch
%{?selinux_requires}

%description    selinux
The %{name}-selinux package contains selinux policy for the %{name} daemon.

%prep
%{gpgverify} --keyring='%{SOURCE2}' --signature='%{SOURCE10}' --data='%{SOURCE0}'
%{gpgverify} --keyring='%{SOURCE2}' --signature='%{SOURCE11}' --data='%{SOURCE1}'

%setup -q

# selinux
%autosetup -D -T -a 1 -p 1

%if 0%{?rhel} != 0
%setup -q -D -T -b 20
%endif

# generate rules for python
sed -i "s|%python2_path%|`readlink -f %{__python2}`|g" rules.d/*.rules
sed -i "s|%python3_path%|`readlink -f %{__python3}`|g" rules.d/*.rules

# Detect run time linker directly from bash
interpret=`readelf -e /usr/bin/bash \
    | grep Requesting \
    | sed 's/.$//' \
    | rev | cut -d" " -f1 \
    | rev`

sed -i "s|%ld_so_path%|`realpath $interpret`|g" rules.d/*.rules

%build
cp INSTALL INSTALL.tmp

# necessary for updating CFLAGS below
%set_build_flags

%if 0%{?rhel} != 0
export CFLAGS="$CFLAGS -I%{_builddir}/uthash-2.3.0/include"
%endif

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

# selinux
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%install
%make_install
install -p -m 644 -D init/%{name}-tmpfiles.conf %{buildroot}/%{_tmpfilesdir}/%{name}.conf
install -p -D -m 0644 %{SOURCE3} %{buildroot}%{_sysusersdir}/%{name}.conf
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
%attr(755,root,root) %dir %{_datadir}/%{name}
%attr(755,root,root) %dir %{_datadir}/%{name}/sample-rules
%attr(644,root,root) %{_datadir}/%{name}/default-ruleset.known-libs
%attr(644,root,root) %{_datadir}/%{name}/sample-rules/*
%attr(644,root,root) %{_datadir}/%{name}/fapolicyd-magic.mgc
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}/trust.d
%attr(750,root,%{name}) %dir %{_sysconfdir}/%{name}/rules.d
%attr(644,root,root) %{_sysconfdir}/bash_completion.d/*
%ghost %verify(not md5 size mtime) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/rules.d/*
%ghost %verify(not md5 size mtime) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.rules
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}-filter.conf
%config(noreplace) %attr(644,root,%{name}) %{_sysconfdir}/%{name}/%{name}.trust
%ghost %attr(644,root,%{name}) %{_sysconfdir}/%{name}/compiled.rules
%attr(644,root,root) %{_unitdir}/%{name}.service
%attr(644,root,root) %{_tmpfilesdir}/%{name}.conf
%attr(644,root,root) %{_sysusersdir}/%{name}.conf
%attr(755,root,root) %{_bindir}/%{name}-rpm-loader
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

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{name}
%{_datadir}/selinux/devel

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
* Fri Feb 06 2026 Petr Lautrbach <lautrbach@redhat.com> - 1.4.3-3
- Fix 32-bit ELF dynamic section parsing

* Tue Jan 27 2026 Petr Lautrbach <lautrbach@redhat.com> - 1.4.3-2
- Fix binary path of rpm-loader
- Map file with MAP_SHARED instead of MAP_PRIVATE
- Fix segfault when interrupting fapolicyd startup

* Tue Jan 13 2026 Petr Lautrbach <lautrbach@redhat.com> - 1.4.3-1
- fapolicyd-1.4.3
  https://github.com/linux-application-whitelisting/fapolicyd/releases/tag/v1.4.3
  https://github.com/linux-application-whitelisting/fapolicyd-selinux/releases/tag/v1.1

* Wed Nov 26 2025 Petr Lautrbach <lautrbach@redhat.com> - 1.4.2-1
- fapolicyd-1.4.2
  https://github.com/linux-application-whitelisting/fapolicyd/releases/tag/v1.4.2

* Fri Oct 31 2025 Petr Lautrbach <lautrbach@redhat.com> - 1.4.1-1
- Fix deadlock on reconfigure
- On reconfigure, update the trust list and reload the rpm filter

* Thu Oct 30 2025 Petr Lautrbach <lautrbach@redhat.com> - 1.4-1
- fapolicyd-1.4 and fapolicyd-selinux-1.0
  https://github.com/linux-application-whitelisting/fapolicyd/releases/tag/v1.4

* Thu Oct 16 2025 Petr Lautrbach <lautrbach@redhat.com> - 1.3.7-1
- fapolicyd-1.3.7 and fapolicyd-selinux-0.9

* Mon Aug 18 2025 Petr Lautrbach <lautrbach@redhat.com> - 1.3.3-106
- Add /var/lib/fapolicyd to tmpfiles
Resolves: RHEL-104873

* Wed May 28 2025 Radovan Sroka <rsroka@redhat.com> - 1.3.3-105
RHEL 9.7.0 ERRATUM
- RPMDB crashes with SIGBUS when updating the RPMDB repeatedly
Resolves: RHEL-63090
- File /run/fapolicyd differs from RPM expectations
Resolves: RHEL-59626
- fapolicyd.service badly instructs how to start after nss-user-lookup.target
Resolves: RHEL-21871
- fapolicy rule containing 'pattern=normal' produces error
Resolves: RHEL-30020
- "fapolicyd-cli --file add" crashes when processing sockets
Resolves: RHEL-69136

* Wed Jul 19 2023 Radovan Sroka <rsroka@redhat.com> - 1.3.3-100
RHEL 9.5.0 ERRATUM
- rebase to fapolicyd-1.3.3 and fapolicyd-selinux-0.7
Resolves: RHEL-36285

* Wed Jul 19 2023 Radovan Sroka <rsroka@redhat.com> - 1.3.2-100
RHEL 9.3.0 ERRATUM
- Rebase fapolicyd to the latest stable version
Resolves: RHEL-430
- fapolicyd can leak FDs and never answer request, causing target process to hang forever
Resolves: RHEL-621
- RFE: send rule number to fanotify so it gets audited
Resolves: RHEL-624
- fapolicyd needs to make sure the FD limit is never reached
Resolves: RHEL-623
- fapolicyd still allows execution of a program after "untrusting" it
Resolves: RHEL-622
- Default q_size doesn't match manpage's one
Resolves: RHEL-627
- fapolicyd-cli --update then mount/umount twice causes fapolicyd daemon to block (state 'D')
Resolves: RHEL-817
- Fix broken backwards compatibility backend numbers
Resolves: RHEL-730
- SELinux prevents the fapolicyd from reading symlink (cert_t)
Resolves: RHEL-816

* Mon Jan 30 2023 Radovan Sroka <rsroka@redhat.com> - 1.1.3-104
RHEL 9.2.0 ERRATUM
- statically linked app can execute untrusted app
Resolves: rhbz#2097077
- fapolicyd ineffective with systemd DynamicUser=yes
Resolves: rhbz#2136802
- Starting manually fapolicyd while the service is already running breaks the system
Resolves: rhbz#2160517
- Cannot execute /usr/libexec/grepconf.sh when falcon-sensor is enabled
Resolves: rhbz#2160518
- fapolicyd: Introduce filtering of rpmdb
Resolves: RHEL-192

* Fri Aug 05 2022 Radovan Sroka <rsroka@redhat.com> - 1.1.3-102
RHEL 9.1.0 ERRATUM
- rebase fapolicyd to the latest stable vesion
Resolves: rhbz#2100041
- fapolicyd gets way too easily killed by OOM killer
Resolves: rhbz#2097385
- fapolicyd does not correctly handle SIGHUP
Resolves: rhbz#2070655
- Introduce ppid rule attribute
Resolves: rhbz#2102558
- fapolicyd often breaks package updates
Resolves: rhbz#2111244
- drop libgcrypt in favour of openssl
Resolves: rhbz#2111938
- Remove dnf plugin
Resolves: rhbz#2113959
- fapolicyd.rules doesn't advertise that using a username/groupname instead of uid/gid also works
Resolves: rhbz#2115849

* Thu Jun 16 2022 Radovan Sroka <rsroka@redhat.com> - 1.1-104
RHEL 9.1.0 ERRATUM
- CVE-2022-1117 fapolicyd: fapolicyd wrongly prepares ld.so path
Resolves: rhbz#2069123
- Faulty handling of static applications
Resolves: rhbz#2096457

* Sun Apr 3 2022 Radovan Sroka <rsroka@redhat.com> - 1.1-101
RHEL 9.1.0 ERRATUM
- fapolicyd denies access to /usr/lib64/ld-2.28.so
Resolves: rhbz#2067493

* Wed Feb 16 2022 Radovan Sroka <rsroka@redhat.com> - 1.1-100
RHEL 9.0.0 ERRATUM
- rebase to 1.1
Resolves: rhbz#2032408
- introduce rules.d
Resolves: rhbz#2054740
- remove pretrans scriptlet
Resolve: rhbz#2051481

* Tue Dec 14 2021 Zoltan Fridrich <zfridric@redhat.com> - 1.0.4-101
RHEL 9.0.0 ERRATUM
- rebase to 1.0.4
- added rpm_sha256_only option
- added trust.d directory
- allow file names with whitespaces in trust files
- use full paths in trust files
Resolves: rhbz#2032408
- fix libc.so getting identified as application/x-executable
Resolves: rhbz#2015307
- fix selinux DSP module definition in spec file
Resolves: rhbz#2014449

* Mon Aug 09 2021 Mohan Boddu <mboddu@redhat.com> - 1.0.3-4
- Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
  Related: rhbz#1991688

* Tue Jul 20 2021 Radovan Sroka <rsroka@redhat.com> - 1.0.3-3
RHEL 9 BETA
- SELinux prevents fapolicyd from watch_mount/watch_with_perm on /dev/shm
Resolves: rhbz#1932225
Resolves: rhbz#1977731

* Thu Apr 15 2021 Mohan Boddu <mboddu@redhat.com> - 1.0.3-2
- Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

* Thu Apr 01 2021 Radovan Sroka <rsroka@redhat.com> - 1.0.3-1
- rebase to 1.0.3
- sync fedora with rhel

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 1.0.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Wed Jan 06 2021 Radovan Sroka <rsroka@redhat.com> - 1.0.2-1
- rebase to 1.0.2
- enabled make check
- dnf-plugin is now required subpackage

* Mon Nov 16 2020 Radovan Sroka <rsroka@redhat.com> - 1.0.1-1
- rebase to 1.0.1
- introduced uthash dependency
- SELinux prevents the fapolicyd process from writing to /run/dbus/system_bus_socket
Resolves: rhbz#1874491
- SELinux prevents the fapolicyd process from writing to /var/lib/rpm directory
Resolves: rhbz#1876538

* Mon Jul 27 2020 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Wed Jun 24 2020 Radovan Sroka <rsroka@redhat.com> - 1.0-3
- backported few cosmetic small patches from upstream master
- rebase selinux tarbal to v0.3
- file context pattern for /run/fapolicyd.pid is missing
Resolves: rhbz#1834674

* Tue May 26 2020 Miro Hrončok <mhroncok@redhat.com> - 1.0-2
- Rebuilt for Python 3.9

* Mon May 25 2020 Radovan Sroka <rsroka@redhat.com> - 1.0-1
- rebase fapolicyd to 1.0
- allowed sys_ptrace for user namespace

* Mon Mar 23 2020 Radovan Sroka <rsroka@redhat.com> - 0.9.4-1
- rebase fapolicyd to 0.9.4
- polished the pattern detection engine
- rpm backend now drops most of the files in /usr/share/ to dramatically reduce
  memory consumption and improve startup speed
- the commandline utility can now delete the lmdb trust database and manage
  the file trust source

* Mon Feb 24 2020 Radovan Sroka <rsroka@redhat.com> - 0.9.3-1
- rebase fapolicyd to 0.9.3
- dramatically improved startup time
- fapolicyd-cli has picked up --list and --ftype commands to help debug/write policy
- file type identification has been improved
- trust database statistics have been added to the reports

* Tue Feb 04 2020 Radovan Sroka <rsroka@redhat.com> - 0.9.2-2
- Label all fifo_file as fapolicyd_var_run_t in /var/run.
- Allow fapolicyd_t domain to create fifo files labeled as
  fapolicyd_var_run_t

* Fri Jan 31 2020 Radovan Sroka <rsroka@redhat.com> - 0.9.2-1
- rebase fapolicyd to 0.9.2
- allows watched mount points to be specified by file system types
- ELF file detection was improved
- the rules have been rewritten to express the policy based on subject
  object trust for better performance and reliability
- exceptions for dracut and ansible were added to the rules to avoid problems
  under normal system use
- adds an admin defined trust database (fapolicyd.trust)
- setting boost, queue, user, and group on the daemon
  command line are deprecated

* Tue Jan 28 2020 Fedora Release Engineering <releng@fedoraproject.org> - 0.9-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Tue Nov 05 2019 Marek Tamaskovic <mtamasko@redhat.com> - 0.9-3
- Updated fapolicyd-selinux subpackage to v0.2
  Selinux subpackage is recommended for fapolicyd.

* Mon Oct 07 2019 Radovan Sroka <rsroka@redhat.com> - 0.9-2
- Added fapolicyd-selinux subpackage

* Mon Oct 07 2019 Radovan Sroka <rsroka@redhat.com> - 0.9-1
- rebase to v0.9

* Thu Oct 03 2019 Miro Hrončok <mhroncok@redhat.com> - 0.8.10-2
- Rebuilt for Python 3.8.0rc1 (#1748018)

* Wed Aug 28 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.10-1
- rebase to 0.8.10
- generate python paths dynamically

* Mon Aug 19 2019 Miro Hrončok <mhroncok@redhat.com> - 0.8.9-5
- Rebuilt for Python 3.8

* Thu Jul 25 2019 Fedora Release Engineering <releng@fedoraproject.org> - 0.8.9-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Mon Jun 10 22:13:18 CET 2019 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 0.8.9-3
- Rebuild for RPM 4.15

* Mon Jun 10 15:42:01 CET 2019 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 0.8.9-2
- Rebuild for RPM 4.15

* Mon May 06 2019 Radovan Sroka <rsroka@redhat.com> - 0.8.9-1
- New upstream release

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
