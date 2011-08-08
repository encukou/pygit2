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

cdef extern from "Python.h":
    cdef PyErr_SetFromErrno(type)

cdef extern from "git2.h":
    # types.h
    ctypedef long git_time_t

    cdef struct git_repository
    cdef struct git_object
    cdef struct git_tree_entry
    cdef struct git_tree
    cdef struct git_tag
    cdef struct git_commit
    cdef struct git_revwalk
    cdef struct git_time:
        git_time_t time
        int offset
    cdef struct git_signature:
        char *name
        char *email
        git_time when
    ctypedef enum git_otype:
        pass

    # oid.h
    ctypedef struct git_oid:
        pass
    int git_oid_fromstr(git_oid *out, char *str)
    void git_oid_fromraw(git_oid *out, unsigned char *raw)
    void git_oid_fmt(char *str, git_oid *oid)

    # commit.h
    char *git_commit_message_short(git_commit *commit)
    char *git_commit_message(git_commit *commit)
    int git_commit_lookup(git_commit **commit, git_repository *repo, git_oid *id)

    # object.h
    int git_object_lookup(git_object **object, git_repository *repo,
            git_oid *id, git_otype type)
    git_otype git_object_type(git_object *obj)
    git_oid *git_object_id(git_object *obj)
    void git_object_close(git_object *object)

    # repository.h
    int git_repository_open(git_repository **repository, char *path)

    # revwalk.h
    void git_revwalk_sorting(git_revwalk *walk, unsigned int sort_mode)
    int git_revwalk_new(git_revwalk **walker, git_repository *repo)
    void git_revwalk_free(git_revwalk *walk)
    int git_revwalk_push(git_revwalk *walk, git_oid *oid)
    int git_revwalk_next(git_oid *oid, git_revwalk *walk)
    int git_revwalk_hide(git_revwalk *walk, git_oid *oid)
    void git_revwalk_reset(git_revwalk *walker)

    # signature.h
    int git_signature_new(git_signature **sig_out, char *name, char *email, git_time_t time, int offset)

    # status.h
    int git_status_foreach(git_repository *repo, int (*callback)(char *, unsigned int, void *), void *payload)

    # tag.h
    git_otype git_tag_type(git_tag *tag)
    git_oid *git_tag_target_oid(git_tag *tag)
    char *git_tag_name(git_tag *tag)
    git_signature *git_tag_tagger(git_tag *tag)
    char *git_tag_message(git_tag *tag)
    int git_tag_create(git_oid *oid, git_repository *repo, char *tag_name, git_object *target, git_signature *tagger, char *message, int force)

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

# Workaround for Cython bug 92 (http://trac.cython.org/cython_trac/ticket/92)
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

cdef Error_set(int err):
    assert err < 0
    if err == git2.GIT_ENOTFOUND:
        # KeyError expects the arg to be the missing key. If the caller
        # called this instead of Error_set_py_obj, it means we don't
        # know the key, but nor should we use git_lasterror.
        raise KeyError(None)
    elif err == git2.GIT_EOSERR:
        PyErr_SetFromErrno(GitError)
    raise Error_type(err)(git_lasterror())

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

cdef build_person(git_signature *signature):
    return (signature.name, signature.email,
            signature.when.time, signature.when.offset)

cdef signature_converter(value, git_signature **signature):
    cdef int err

    name, email, time, offset = value

    err = git_signature_new(signature, name, email, time, offset);
    if err < 0:
        Error_set(err);

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

    property type:
        def __get__(self):
            return git_object_type(self.obj)

cdef class Commit(_GitObject):
    cdef git_commit* _commit(self):
        return <git_commit*>self.obj

    property message_short:
        def __get__(self):
            return git_commit_message_short(self._commit())

    property message:
        def __get__(self):
            return git_commit_message(self._commit())

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
    cdef _target

    cdef git_tag* _tag(self):
        return <git_tag*>self.obj

    property target:
        def __get__(self):
            cdef git_oid *target_oid
            cdef git_otype target_type

            if self._target is None:
                target_oid = git_tag_target_oid(self._tag())
                target_type = git_tag_type(self._tag())
                self._target = self.repo.lookup_object(target_oid, target_type)
            if self._target is None:
                raise RuntimeError

            return self._target

    property name:
        def __get__(self):
            cdef char *name = git_tag_name(self._tag())
            if name is NULL:
                return None
            return name

    property tagger:
        def __get__(self):
            cdef git_signature *signature = git_tag_tagger(self._tag())
            if signature is NULL:
                return None
            return build_person(signature)

    property message:
        def __get__(self):
            cdef char *message = git_tag_message(self._tag())
            if message is NULL:
                return None
            return message

cdef class Walker(object):
    cdef git_revwalk *walk
    cdef Repository repo

    def __cinit__(self, repo):
        self.repo = repo

    def __del__(self):
        git_revwalk_free(self.walk)

    def __next__(self):
        cdef git_oid oid
        cdef int err
        cdef git_commit *commit
        cdef Commit py_commit

        err = git_revwalk_next(&oid, self.walk)
        if err < 0:
            raise Error_set(err)

        err = git_commit_lookup(&commit, self.repo.repo, &oid);
        if err < 0:
            return Error_set(err);

        py_commit = Commit()
        py_commit.obj = <git_object*>commit
        py_commit.repo = self.repo
        return py_commit

    def __iter__(self):
        return self

    def hide(self, hex):
        cdef int err
        cdef git_oid oid

        py_str_to_git_oid(hex, &oid)

        err = git_revwalk_hide(self.walk, &oid)
        if err < 0:
            return Error_set(err)

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

    cpdef create_tag(self, char* tag_name, oid, git_otype target_type, tagger, char *message):
        cdef git_oid c_oid
        cdef git_signature *c_tagger
        cdef git_object *target
        cdef char hex[git2.GIT_OID_HEXSZ + 1]

        py_str_to_git_oid(oid, &c_oid)
        signature_converter(tagger, &c_tagger)

        err = git_object_lookup(&target, self.repo, &c_oid, target_type)
        if err < 0:
            git_oid_fmt(hex, &c_oid)
            hex[git2.GIT_OID_HEXSZ] = '\0'
            Error_set_str(err, hex);

        err = git_tag_create(&c_oid, self.repo, tag_name, target, c_tagger, message, 0)
        git_object_close(target)
        if err < 0:
            raise RuntimeError

        return git_oid_to_py_str(&c_oid)

    def walk(self, value, unsigned int sort):
        cdef git_revwalk *walk
        cdef Walker walker
        cdef git_oid oid

        if value is not None and not isinstance(value, basestring):
            raise TypeError(value)

        err = git_revwalk_new(&walk, self.repo);
        if err < 0:
            return Error_set(err);

        try:
            # Sort
            git_revwalk_sorting(walk, sort)

            # Push
            if value is not None:
                py_str_to_git_oid(value, &oid)
                err = git_revwalk_push(walk, &oid)
                if err < 0:
                    Error_set(err)

            walker = Walker(self)
            walker.walk = walk
            return walker

        except Exception:
            git_revwalk_free(walk)
            raise

    def __getitem__(self, value):
        cdef git_oid oid

        py_str_to_git_oid(value, &oid)

        return self.lookup_object(&oid, GIT_OBJ_ANY)
