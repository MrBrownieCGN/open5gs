# Copyright (C) 2026 by Daniel Brune <daniel.brune.so@outlook.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

test5gc_gethssav_sources = files('''
    abts-main.c
    gethssav-test.c
'''.split())

test5gc_gethssav_exe = executable('gethssav',
    sources : test5gc_gethssav_sources,
    c_args : testunit_core_cc_flags,
    dependencies : [libtest5gc_dep, libsbi_dep])

test('gethssav',
    test5gc_gethssav_exe,
    is_parallel : false,
    suite: ['gethssav', '5gc'])
