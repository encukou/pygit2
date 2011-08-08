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

cimport git2
cdef extern from "git2.h":

    # types.h
    cdef struct git_repository

    # errors.h
    char * git_lasterror()

    # repository.h
    int git_repository_open(git_repository **repository, char *path)

    # status.h
    int git_status_foreach(git_repository *repo, int (*callback)(char *, unsigned int, void *), void *payload)

# Workaound for Cython bug 471 (http://trac.cython.org/cython_trac/ticket/471)
GIT_OBJ_COMMIT = git2.GIT_OBJ_COMMIT
GIT_OBJ_BLOB = git2.GIT_OBJ_BLOB
GIT_OBJ_ANY = git2.GIT_OBJ_ANY

GIT_REF_OID = git2.GIT_REF_OID
GIT_REF_SYMBOLIC = git2.GIT_REF_SYMBOLIC

GIT_SORT_TIME = git2.GIT_SORT_TIME
GIT_SORT_REVERSE = git2.GIT_SORT_REVERSE

GIT_STATUS_CURRENT = git2.GIT_STATUS_CURRENT
GIT_STATUS_WT_DELETED = git2.GIT_STATUS_WT_DELETED
GIT_STATUS_WT_MODIFIED = git2.GIT_STATUS_WT_MODIFIED
GIT_STATUS_WT_NEW = git2.GIT_STATUS_WT_NEW
GIT_STATUS_INDEX_MODIFIED = git2.GIT_STATUS_INDEX_MODIFIED
GIT_STATUS_INDEX_DELETED = git2.GIT_STATUS_INDEX_DELETED
GIT_STATUS_INDEX_NEW = git2.GIT_STATUS_INDEX_NEW

class GitError(Exception):
    pass

cdef Error_type(int err):
    """Return the correct Python exception class based on err code
    """
    return {
            git2.GIT_ENOTFOUND: KeyError,
            git2.GIT_EOSERR: OSError,
            git2.GIT_ENOTOID: ValueError,
            git2.GIT_ENOMEM: MemoryError,
            git2.GIT_EREVWALKOVER: StopIteration,
        }.get(err, GitError)

cdef git_exception(err, message):
    """Raise an appropriate Git exception

    (Error_set_str in the C version)
    """
    if err == git2.GIT_ENOTFOUND:
        raise KeyError, message
    else:
        raise Error_type(err), "%s: %s" % (message, git_lasterror())

cdef int read_status_cb(char *path, unsigned int status_flags,
                          void *payload_dict):
    """ This is the callback that will be called in git_status_foreach. It
    will be called for every path.
    """
    (<object>payload_dict)[path] = status_flags

    return git2.GIT_SUCCESS;


cdef class Repository(object):
    cdef git_repository* repo

    def __cinit__(self, path):
        cdef int err
        err = git_repository_open(&self.repo, path)
        if err < 0:
            raise git_exception(err, path)

    def status(self):
        payload_dict = {}
        git_status_foreach(self.repo, read_status_cb, <void*>payload_dict)
        return payload_dict
