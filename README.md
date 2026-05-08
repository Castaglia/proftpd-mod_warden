proftpd-mod_warden
==================

Status
------
[![GitHub Actions CI Status](https://github.com/Castaglia/proftpd-mod_warden/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Castaglia/proftpd-mod_warden/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-GPL-brightgreen.svg)](https://img.shields.io/badge/license-GPL-brightgreen.svg)

Synopsis
--------
The `mod_warden` module for ProFTPD actively deletes blacklisted files for
chrooted sessions (via `DefaultRoot` or via `<Anonymous>` logins).  This can
help to mitigate some attacks, _e.g._ the "Roaring Beast" FreeBSD exploit.

For further module documentation, see [mod_warden.html](https://htmlpreview.github.io/?https://github.com/Castaglia/proftpd-mod_warden/blob/master/mod_warden.html).
