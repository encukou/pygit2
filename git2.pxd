"""
Copyright 2011 Petr Viktorin

This file is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2,
as published by the Free Software Foundation.

In addition to the permissions in the GNU General Public License,
the authors give you unlimited permission to link the compiled
version of this file into combinations with other programs,
and to distribute those combinations without any restriction
coming from the use of this file.  (The General Public License
restrictions do apply in other respects; for example, they cover
modification of the file, and distribution when not linked into
a combined executable.)

This file is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING.  If not, write to
the Free Software Foundation, 51 Franklin Street, Fifth Floor,
Boston, MA 02110-1301, USA.
"""

cdef extern from "git2.h":
    enum git_otype:
        GIT_OBJ_ANY
        GIT_OBJ_BAD
        GIT_OBJ_COMMIT
        GIT_OBJ_TREE
        GIT_OBJ_BLOB
        GIT_OBJ_TAG
        GIT_OBJ_OFS_DELTA
        GIT_OBJ_REF_DELTA

    enum:
        GIT_REF_OID
        GIT_REF_SYMBOLIC
        GIT_REF_LISTALL

        GIT_SORT_TIME
        GIT_SORT_REVERSE

        GIT_STATUS_CURRENT
        GIT_STATUS_WT_DELETED
        GIT_STATUS_WT_MODIFIED
        GIT_STATUS_WT_NEW
        GIT_STATUS_INDEX_MODIFIED
        GIT_STATUS_INDEX_DELETED
        GIT_STATUS_INDEX_NEW

        GIT_ENOTFOUND
        GIT_EOSERR
        GIT_ENOTOID
        GIT_ENOMEM
        GIT_EREVWALKOVER

        GIT_SUCCESS

        GIT_OID_HEXSZ

    char * git_lasterror()
