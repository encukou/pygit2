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

    # types.h
    cdef struct git_repository
    cdef struct git_object
    cdef struct git_tree_entry
    cdef struct git_tree
    ctypedef enum git_otype:
        pass

    # oid.h
    ctypedef struct git_oid:
        pass
    int git_oid_fromstr(git_oid *out, char *str)
    void git_oid_fromraw(git_oid *out, unsigned char *raw)
    void git_oid_fmt(char *str, git_oid *oid)

    # object.h
    int git_object_lookup(git_object **object, git_repository *repo,
            git_oid *id, git_otype type)
    git_otype git_object_type(git_object *obj)
    git_oid *git_object_id(git_object *obj)

    # repository.h
    int git_repository_open(git_repository **repository, char *path)

    # status.h
    int git_status_foreach(git_repository *repo, int (*callback)(char *, unsigned int, void *), void *payload)

    # tree.h
    git_tree_entry *git_tree_entry_byindex(git_tree *tree, unsigned int idx)
    git_tree_entry *git_tree_entry_byname(git_tree *tree, char *filename)
    unsigned int git_tree_entrycount(git_tree *tree)
    git_oid *git_tree_entry_id(git_tree_entry *entry)
    char *git_tree_entry_name(git_tree_entry *entry)
    unsigned int git_tree_entry_attributes(git_tree_entry *entry)

cdef git_lasterror():
    cdef char * lasterror
    lasterror = git2.git_lasterror()

    if lasterror is NULL:
        return "No error"
    else:
        return lasterror

# Workaround for Cython bug 471 (http://trac.cython.org/cython_trac/ticket/471)
cimport git2
GIT_OBJ_ANY = git2.GIT_OBJ_ANY
GIT_OBJ_BAD = git2.GIT_OBJ_BAD
GIT_OBJ_COMMIT = git2.GIT_OBJ_COMMIT
GIT_OBJ_TREE = git2.GIT_OBJ_TREE
GIT_OBJ_BLOB = git2.GIT_OBJ_BLOB
GIT_OBJ_TAG = git2.GIT_OBJ_TAG
GIT_OBJ_OFS_DELTA = git2.GIT_OBJ_OFS_DELTA
GIT_OBJ_REF_DELTA = git2.GIT_OBJ_REF_DELTA

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

cdef class Repository

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

cdef Error_set_str(int err, message):
    """Raise an appropriate Git exception
    """
    if err == git2.GIT_ENOTFOUND:
        raise KeyError, message
    else:
        raise Error_type(err), "%s: %s" % (message, git_lasterror())

cdef Error_set_py_obj(int err, py_obj):
    assert err < 0

    if err == git2.GIT_ENOTOID and not isinstance(py_obj, basestring):
        raise TypeError("Git object id must be 40 byte hexadecimal str, or 20 byte binary str: %.200s" % type(py_obj).__name__)
    elif err == git2.GIT_ENOTFOUND:
        # KeyError expects the arg to be the missing key.
        raise KeyError(py_obj)

    try:
        message = str(py_obj)
    except Exception:
        message = "<error in __str__>"
    raise Error_type(err)("%s: %s" % (message, git_lasterror()))

cdef int read_status_cb(char *path, unsigned int status_flags,
                          void *payload_dict):
    """ This is the callback that will be called in git_status_foreach. It
    will be called for every path.
    """
    (<object>payload_dict)[path] = status_flags

    return git2.GIT_SUCCESS;

cdef py_str_to_git_oid(py_str, git_oid *oid):
    cdef int err

    if not isinstance(py_str, basestring):
        Error_set_py_obj(git2.GIT_ENOTOID, py_str)

    hex_or_bin = py_str

    if len(py_str) == 20:
        git_oid_fromraw(oid, py_str)
    else:
        err = git_oid_fromstr(oid, py_str)
        if err < 0:
            raise Error_set_py_obj(err, py_str)

cdef git_oid_to_py_str(git_oid *oid):
    cdef char hex[git2.GIT_OID_HEXSZ]

    git_oid_fmt(hex, oid)
    return hex

cdef class TreeEntry(object):
    cdef git_tree_entry *entry
    cdef tree

    property sha:
        def __get__(self):
            return git_oid_to_py_str(git_tree_entry_id(self.entry))

    property name:
        def __get__(self):
            return git_tree_entry_name(self.entry)

    property attributes:
        def __get__(self):
            return git_tree_entry_attributes(self.entry)

    def to_object(self):
        cdef git_oid *entry_oid

        entry_oid = git_tree_entry_id(self.entry);
        return (<Tree?>self.tree).repo.lookup_object(entry_oid, GIT_OBJ_ANY)

cdef _tree_entry_wrap(git_tree_entry *entry, tree):
    py_entry = TreeEntry()
    py_entry.entry = entry
    py_entry.tree = tree
    return py_entry

cdef class _GitObject(object):
    cdef git_object* obj
    cdef Repository repo

    property sha:
        def __get__(self):
            cdef git_oid *oid

            oid = git_object_id(self.obj)
            if not oid:
                return None

            return git_oid_to_py_str(oid)

cdef class Commit(_GitObject):
    pass

cdef class Tree(_GitObject):
    cdef git_tree* _tree(self):
        return <git_tree*>self.obj

    cdef int _fix_index(self, long index) except? -5:
        cdef size_t len
        cdef long slen

        len = slen = git_tree_entrycount(<git_tree*>self.obj);
        print index, -slen
        if index >= slen:
            raise IndexError(index)
        elif index < -slen:
            raise IndexError(index)

        # This function is called via __getitem__, which doesn't do negative
        # index rewriting, so we have to do it manually.
        if index < 0:
            index = len + index
        return index

    cdef _getitem_by_index(self, long index):
        cdef git_tree_entry *entry

        entry = git_tree_entry_byindex(self._tree(), self._fix_index(index))
        if entry is NULL:
            raise IndexError(index)
        return _tree_entry_wrap(entry, self)

    cdef _getitem_by_name(self, name):
        cdef git_tree_entry *entry

        entry = git_tree_entry_byname(self._tree(), name);
        if entry is NULL:
            raise KeyError(name)
        return _tree_entry_wrap(entry, self)

    def __getitem__(self, value):
        if isinstance(value, basestring):
            return self._getitem_by_name(value)
        elif isinstance(value, int):
            return self._getitem_by_index(value)
        else:
            raise TypeError("Tree entry index must be int or str, not %.200s" %
                type(value).__name__)

    def __iter__(self):
        return TreeIter(self)

    def __len__(self):
        assert self._tree()
        return git_tree_entrycount(self._tree())

    def __contains__(self, char *name):
        return git_tree_entry_byname(self._tree(), name) is not NULL

cdef class TreeIter(object):
    cdef Tree owner
    cdef int i

    def __cinit__(self, owner):
        self.owner = owner
        self.i = 0

    def __next__(self):
        cdef git_tree_entry *tree_entry

        tree_entry = git_tree_entry_byindex(self.owner._tree(), self.i)
        if tree_entry is NULL:
            raise StopIteration

        self.i += 1
        return _tree_entry_wrap(tree_entry, self.owner)

cdef class Blob(_GitObject):
    pass

cdef class Tag(_GitObject):
    pass

cdef class Repository(object):
    cdef git_repository* repo

    def __cinit__(self, path):
        cdef int err
        err = git_repository_open(&self.repo, path)
        if err < 0:
            raise Error_set_str(err, path)

    cdef lookup_object(self, git_oid *oid, git_otype type):
        cdef int err
        cdef char hex[git2.GIT_OID_HEXSZ + 1]
        cdef git_object *obj
        cdef git_otype otype
        cdef _GitObject py_obj

        err = git_object_lookup(&obj, self.repo, oid, type);
        if err < 0:
            git_oid_fmt(hex, oid);
            hex[git2.GIT_OID_HEXSZ] = '\0';
            return Error_set_str(err, hex);

        if obj is NULL:
            raise MemoryError()

        otype = git_object_type(obj)
        if otype == GIT_OBJ_COMMIT:
            cls = Commit
        elif otype == GIT_OBJ_TREE:
            cls = Tree
        elif otype == GIT_OBJ_BLOB:
            cls = Blob
        elif otype == GIT_OBJ_TAG:
            cls = Tag
        else:
            raise RuntimeError("Bad Git object type (%s)" % otype)

        py_obj = cls()
        py_obj.obj = obj
        py_obj.repo = self
        return py_obj

    def status(self):
        payload_dict = {}
        git_status_foreach(self.repo, read_status_cb, <void*>payload_dict)
        return payload_dict

    def __getitem__(self, value):
        cdef git_oid oid

        py_str_to_git_oid(value, &oid)

        return self.lookup_object(&oid, GIT_OBJ_ANY)
