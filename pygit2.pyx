# Copyright 2011 Petr Viktorin

# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2,
# as published by the Free Software Foundation.

# In addition to the permissions in the GNU General Public License,
# the authors give you unlimited permission to link the compiled
# version of this file into combinations with other programs,
# and to distribute those combinations without any restriction
# coming from the use of this file.  (The General Public License
# restrictions do apply in other respects; for example, they cover
# modification of the file, and distribution when not linked into
# a combined executable.)

# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.

"""Python bindings for libgit2.

pygit2 is a set of Python bindings to the libgit2 linkable C Git library.
"""
cimport cython

cdef extern from "Python.h":
    cdef PyErr_SetFromErrno(type)

cdef extern from "stdlib.h":
    void* malloc(size_t size)
    void free(void* ptr)

cdef extern from "git2.h":
    # common.h
    ctypedef struct git_strarray:
        char **strings
        size_t count

    void git_strarray_free(git_strarray *array)

    # types.h
    ctypedef long git_time_t

    cdef struct git_repository
    cdef struct git_object
    cdef struct git_tree_entry
    cdef struct git_tree
    cdef struct git_tag
    cdef struct git_commit
    cdef struct git_revwalk
    cdef struct git_odb
    cdef struct git_odb_object
    cdef struct git_reference
    cdef struct git_index
    cdef struct git_time:
        git_time_t time
        int offset
    cdef struct git_signature:
        char *name
        char *email
        git_time when
    ctypedef enum git_otype:
        pass
    ctypedef enum git_rtype:
        pass
    ctypedef long git_off_t

    # oid.h
    ctypedef struct git_oid:
        pass
    int git_oid_fromstr(git_oid *out, char *str)
    void git_oid_fromraw(git_oid *out, unsigned char *raw)
    void git_oid_fmt(char *str, git_oid *oid)

    # commit.h
    char *git_commit_message_encoding(git_commit *commit)
    char *git_commit_message(git_commit *commit)
    int git_commit_lookup(git_commit **commit, git_repository *repo,
        git_oid *id)
    unsigned int git_commit_parentcount(git_commit *commit)
    git_oid *git_commit_parent_oid(git_commit *commit, unsigned int n)
    int git_commit_create(git_oid *oid, git_repository *repo,
        char *update_ref, git_signature *author, git_signature *committer,
        char *message_encoding,
        char *message, git_tree *tree, int parent_count, git_commit *parents[])
    void git_commit_close(git_commit *commit)
    int git_commit_tree(git_tree **tree_out, git_commit *commit)
    git_signature *git_commit_author(git_commit *commit)
    git_signature *git_commit_committer(git_commit *commit)
    git_time_t git_commit_time(git_commit *commit)

    # errors.h
    char *git_lasterror()

    # index.h
    ctypedef struct git_index_time:
        git_time_t seconds
        unsigned int nanoseconds
    cdef struct git_index_entry:
        git_index_time ctime
        git_index_time mtime

        unsigned int dev
        unsigned int ino
        unsigned int mode
        unsigned int uid
        unsigned int gid
        git_off_t file_size

        git_oid oid

        unsigned short flags
        unsigned short flags_extended

        char *path

    unsigned int git_index_entrycount(git_index *index)
    int git_index_add(git_index *index, char *path, int stage)
    int git_index_write(git_index *index)
    git_index_entry * git_index_get(git_index *index, unsigned int n)
    int git_index_find(git_index *index, char *path)
    void git_index_clear(git_index *index)
    int git_index_remove(git_index *index, int position)
    int git_index_read(git_index *index)
    int git_tree_create_fromindex(git_oid *oid, git_index *index)
    void git_index_free(git_index *index)
    int git_index_open(git_index **index, char *index_path)

    # object.h
    int git_object_lookup(git_object **object, git_repository *repo,
            git_oid *id, git_otype type)
    git_otype git_object_type(git_object *obj)
    git_oid *git_object_id(git_object *obj)
    void git_object_close(git_object *object)

    # odb_backend.h
    cdef struct git_odb_backend
    ctypedef struct git_odb_stream:
        git_odb_backend *backend
        int mode

        int (*read)(git_odb_stream *stream, char *buffer, size_t len)
        int (*write)(git_odb_stream *stream, char *buffer, size_t len)
        int (*finalize_write)(git_oid *oid_p, git_odb_stream *stream)
        void (*free)(git_odb_stream *stream)

    # odb.h
    int git_odb_open_wstream(git_odb_stream **stream, git_odb *db, size_t size,
        git_otype type)
    void git_odb_object_close(git_odb_object *object)
    size_t git_odb_object_size(git_odb_object *object)
    void *git_odb_object_data(git_odb_object *object)
    git_otype git_odb_object_type(git_odb_object *object)
    int git_odb_read(git_odb_object **out, git_odb *db, git_oid *id)
    int git_odb_exists(git_odb *db, git_oid *id)

    # repository.h
    ctypedef enum git_repository_pathid:
        GIT_REPO_PATH_WORKDIR
        GIT_REPO_PATH

    int git_repository_open(git_repository **repository, char *path)
    char *git_repository_path(git_repository *repo, git_repository_pathid id)
    git_odb *git_repository_database(git_repository *repo)
    int git_repository_index(git_index **index, git_repository *repo)
    void git_repository_free(git_repository *repo)
    int git_repository_init(git_repository **repo_out, char *path,
            unsigned is_bare)

    # revwalk.h
    void git_revwalk_sorting(git_revwalk *walk, unsigned int sort_mode)
    int git_revwalk_new(git_revwalk **walker, git_repository *repo)
    void git_revwalk_free(git_revwalk *walk)
    int git_revwalk_push(git_revwalk *walk, git_oid *oid)
    int git_revwalk_next(git_oid *oid, git_revwalk *walk)
    int git_revwalk_hide(git_revwalk *walk, git_oid *oid)
    void git_revwalk_reset(git_revwalk *walker)

    # refs.h
    int git_reference_lookup(git_reference **reference_out,
        git_repository *repo, char *name)
    char *git_reference_target(git_reference *ref)
    int git_reference_set_target(git_reference *ref, char *target)
    int git_reference_create_oid(git_reference **ref_out, git_repository *repo,
        char *name, git_oid *id, int force)
    char *git_reference_name(git_reference *ref)
    git_oid *git_reference_oid(git_reference *ref)
    int git_reference_set_oid(git_reference *ref, git_oid *id)
    int git_reference_rename(git_reference *ref, char *new_name, int force)
    git_rtype git_reference_type(git_reference *ref)
    int git_reference_resolve(git_reference **resolved_ref, git_reference *ref)
    int git_reference_packall(git_repository *repo)
    int git_reference_listall(git_strarray *array, git_repository *repo,
        unsigned int list_flags)
    int git_reference_delete(git_reference *ref)
    int git_reference_create_symbolic(git_reference **ref_out,
        git_repository *repo, char *name, char *target, int force)

    # signature.h
    int git_signature_new(git_signature **sig_out, char *name, char *email,
        git_time_t time, int offset)

    # status.h
    int git_status_foreach(git_repository *repo, int (*callback)(char *,
        unsigned int, void *), void *payload)

    # tag.h
    git_otype git_tag_type(git_tag *tag)
    git_oid *git_tag_target_oid(git_tag *tag)
    char *git_tag_name(git_tag *tag)
    git_signature *git_tag_tagger(git_tag *tag)
    char *git_tag_message(git_tag *tag)
    int git_tag_create(git_oid *oid, git_repository *repo, char *tag_name,
        git_object *target, git_signature *tagger, char *message, int force)

    # tree.h
    git_tree_entry *git_tree_entry_byindex(git_tree *tree, unsigned int idx)
    git_tree_entry *git_tree_entry_byname(git_tree *tree, char *filename)
    unsigned int git_tree_entrycount(git_tree *tree)
    git_oid *git_tree_entry_id(git_tree_entry *entry)
    char *git_tree_entry_name(git_tree_entry *entry)
    unsigned int git_tree_entry_attributes(git_tree_entry *entry)
    int git_tree_lookup(git_tree **tree, git_repository *repo, git_oid *id)
    void git_tree_close(git_tree *tree)

# Constants
# Workaround for Cython bug 92 (http://trac.cython.org/cython_trac/ticket/92)
cimport git2

# Object types
GIT_OBJ_ANY = git2.GIT_OBJ_ANY
GIT_OBJ_COMMIT = git2.GIT_OBJ_COMMIT
GIT_OBJ_TREE = git2.GIT_OBJ_TREE
GIT_OBJ_BLOB = git2.GIT_OBJ_BLOB
GIT_OBJ_TAG = git2.GIT_OBJ_TAG
GIT_OBJ_BAD = git2.GIT_OBJ_BAD

# Revwalk sort types
GIT_SORT_NONE = git2.GIT_SORT_NONE
GIT_SORT_TOPOLOGICAL = git2.GIT_SORT_TOPOLOGICAL
GIT_SORT_TIME = git2.GIT_SORT_TIME
GIT_SORT_REVERSE = git2.GIT_SORT_REVERSE

# Reference types
GIT_REF_OID = git2.GIT_REF_OID
GIT_REF_SYMBOLIC = git2.GIT_REF_SYMBOLIC
GIT_REF_PACKED = git2.GIT_REF_PACKED
GIT_REF_LISTALL = git2.GIT_REF_LISTALL

## Git status flags
GIT_STATUS_CURRENT = git2.GIT_STATUS_CURRENT

# Flags for index status
GIT_STATUS_INDEX_NEW = git2.GIT_STATUS_INDEX_NEW
GIT_STATUS_INDEX_MODIFIED = git2.GIT_STATUS_INDEX_MODIFIED
GIT_STATUS_INDEX_DELETED = git2.GIT_STATUS_INDEX_DELETED

# Flags for worktree status
GIT_STATUS_WT_NEW = git2.GIT_STATUS_WT_NEW
GIT_STATUS_WT_MODIFIED = git2.GIT_STATUS_WT_MODIFIED
GIT_STATUS_WT_DELETED = git2.GIT_STATUS_WT_DELETED

# Flags for ignored files
GIT_STATUS_IGNORED = git2.GIT_STATUS_IGNORED

import sys

from cpython cimport PY_MAJOR_VERSION

cdef bint py3
py3 = PY_MAJOR_VERSION >= 3

cdef filesystemencoding = sys.getfilesystemencoding()

cdef class Repository
cdef class GitObject
cdef class Index
cdef class Tree

class GitError(Exception):
    """Thrown when something is wrong in libgit2."""
    pass

cdef Error_type(int err):
    """Return the correct Python exception class based on Git error code
    """
    if err == git2.GIT_ENOTFOUND:
        return KeyError
    elif err == git2.GIT_EOSERR:
        return OSError
    elif err == git2.GIT_ENOTOID:
        return ValueError
    elif err == git2.GIT_ENOMEM:
        return MemoryError
    elif err == git2.GIT_EREVWALKOVER:
        return StopIteration
    else:
        return GitError

cdef err_str(message, int err):
    """Handle the given Git error code and a string message

    Does nothing if no error occured.
    """
    if err >= 0:
        return
    elif err == git2.GIT_ENOTFOUND:
        raise KeyError, message
    else:
        raise Error_type(err), "%s: %s" % (message, git_lasterror())

cdef err_obj(py_obj, int err):
    """Handle the given Git error code and associated Python object

    Does nothing if no error occured.
    """
    if err >= 0:
        return
    elif err == git2.GIT_ENOTOID and not isinstance(py_obj, (bytes, unicode)):
        raise TypeError("Git object id must be 40 byte hexadecimal str, "
                "or 20 byte binary str: %.200s" % type(py_obj).__name__)
    elif err == git2.GIT_ENOTFOUND:
        # KeyError expects the arg to be the missing key.
        raise KeyError(py_obj)

    try:
        message = str(py_obj)
    except Exception:
        message = "<error in __str__>"
    raise Error_type(err)("%s: %s" % (message, git_lasterror()))

cdef err(int err):
    """Handle the given Git error code

    Does nothing if no error occured.
    """

    if err >= 0:
        return
    elif err == git2.GIT_ENOTFOUND:
        # KeyError expects the arg to be the missing key. If the caller
        # called this instead of err_obj, it means we don't know the key, but
        # we shouldn't use git_lasterror anyway.
        raise KeyError(None)
    elif err == git2.GIT_EOSERR:
        PyErr_SetFromErrno(GitError)
    raise Error_type(err)(git_lasterror())

cdef encode_path(py_path):
    """Encode unicode paths using the filesystem encoding.

    8-bit paths are unchanged,
    """
    if isinstance(py_path, unicode):
        return py_path.encode(filesystemencoding)
    else:
        return py_path

cdef decode_path(char *c_path):
    """On py3k, encode paths using the filesystem encoding.

    Otherwise, the path is unchanged,
    """
    py_path = c_path
    if py3:
        return py_path.decode(filesystemencoding)
    else:
        return py_path

cdef git_otype int_to_loose_object_type(int type_id):
    """Validate and convert a loose object type ID"""
    if type_id in (git2.GIT_OBJ_COMMIT, git2.GIT_OBJ_TREE, git2.GIT_OBJ_BLOB,
            git2.GIT_OBJ_TAG):
        return <git_otype>type_id
    else:
        return git2.GIT_OBJ_BAD

cdef int read_status_cb(char *path, unsigned int status_flags,
                          void *payload_dict):
    """ This is the callback that will be called in git_status_foreach. It
    will be called for every path.
    """
    cdef Repository r
    d, r = (<tuple>payload_dict)
    d[r.decode(path)] = status_flags

    return git2.GIT_SUCCESS

cdef py_str_to_git_oid(py_str, git_oid *oid):
    """Convert a Python string with the a SHA to a git_oid
    """

    if not isinstance(py_str, (bytes, unicode)):
        err_obj(py_str, git2.GIT_ENOTOID)

    if py3 and isinstance(py_str, unicode):
        py_str = py_str.encode('ascii')

    if len(py_str) == 20:
        git_oid_fromraw(oid, py_str)
    else:
        err_obj(py_str, git_oid_fromstr(oid, py_str))

cdef git_oid_to_py_str(git_oid *oid):
    """Convert a git_oid to a Python string with the hex SHA
    """

    cdef char hex[git2.GIT_OID_HEXSZ]

    git_oid_fmt(hex, oid)
    py_hex = hex[:git2.GIT_OID_HEXSZ]
    if py3:
        return py_hex.decode('ascii')
    else:
        return py_hex

class Signature(tuple):
    """A signature with a person's name, e-mail and signing time.

    Used to identify commit authors/committers, tag taggers, etc.
    """

    @property
    def name(self):
        """Name of the person"""
        return self[0]

    @property
    def email(self):
        """E-mail of the person"""
        return self[1]

    @property
    def time(self):
        """Time of the signature"""
        return self[2]

    @property
    def time_offset(self):
        """Time offset of the signature"""
        return self[3]

cdef build_person(git_signature *signature, Repository repo):
    """Build a signature 4-tuple from a git_signature*"""
    return Signature((repo.decode(signature.name),
            repo.decode(signature.email), signature.when.time,
            signature.when.offset))

cdef signature_converter(value, git_signature **signature, Repository repo):
    """Convert a signature 4-tuple to a git_signature*"""

    name, email, time, offset = value
    name = repo.encode(name)
    email = repo.encode(email)

    err(git_signature_new(signature, name, email, time, offset))

cdef _new(cls):
    return cls.__new__(cls)

cdef class TreeEntry(object):
    """A Tree Entry"""

    cdef git_tree_entry *entry
    cdef Tree tree

    def __init__(self):
        raise TypeError('This class cannot be instantiated directly')

    property sha:
        """Hex SHA of this entry's object"""

        def __get__(self):
            return git_oid_to_py_str(git_tree_entry_id(self.entry))

    property name:
        """Filename of this entry"""

        def __get__(self):
            return self.tree.repo.decode(git_tree_entry_name(self.entry))

    property attributes:
        """UNIX file attributes of this entry"""

        def __get__(self):
            return git_tree_entry_attributes(self.entry)

    def to_object(self):
        """Look up the corresponding object in the Repository."""

        cdef git_oid *entry_oid

        entry_oid = git_tree_entry_id(self.entry)
        return (<Tree?>self.tree).repo.lookup_object(entry_oid, GIT_OBJ_ANY)

cdef wrap_tree_entry(git_tree_entry *entry, tree):
    """Internal factory function"""
    cdef TreeEntry py_entry

    py_entry = _new(TreeEntry)
    py_entry.entry = entry
    py_entry.tree = tree
    return py_entry

cdef class GitObject(object):
    """Git object (commit, blob, tree, etc.)"""

    cdef git_object* obj
    cdef Repository repo

    def __init__(self):
        raise TypeError('This class cannot be instantiated directly')

    def __del__(self):
        git_object_close(self.obj)

    property sha:
        """Hex SHA of this object"""

        def __get__(self):
            cdef git_oid *oid

            oid = git_object_id(self.obj)
            if not oid:
                return None

            return git_oid_to_py_str(oid)

    property type:
        """Type number of this object"""

        def __get__(self):
            return git_object_type(self.obj)

    def read_raw(self):
        """Read the raw contents of this object from the repo."""

        cdef git_odb_object *obj

        id = git_object_id(self.obj)
        if not id:
            return None  # in-memory object

        err_obj(self.sha, self.repo.read_raw(&obj, id))

        try:
            return (<char*>git_odb_object_data(obj))[:git_odb_object_size(obj)]
        finally:
            git_odb_object_close(obj)

cdef class Commit(GitObject):
    """Commit object"""

    cdef git_commit* _commit(self):
        return <git_commit*>self.obj

    property message_encoding:
        """The encoding used by this commit."""

        def __get__(self):
            cdef char *encoding = git_commit_message_encoding(self._commit())
            if encoding is NULL:
                return None
            else:
                return encoding.decode('ascii')

    property message:
        """The full message of this commit."""

        def __get__(self):
            return self.repo.decode(git_commit_message(self._commit()))

    property parents:
        """The parent commits of this commit."""

        def __get__(self):
            cdef unsigned int i
            cdef git_oid *parent_oid

            lst = []
            for i in range(git_commit_parentcount(self._commit())):
                parent_oid = git_commit_parent_oid(self._commit(), i)
                if parent_oid is NULL:
                    err(git2.GIT_ENOTFOUND)
                obj = self.repo.lookup_object(parent_oid, git2.GIT_OBJ_COMMIT)
                lst.append(obj)
            return lst

    property commit_time:
        """The commit time (i.e. committer time) of this commit."""

        def __get__(self):
            return git_commit_time(self._commit())

    property committer:
        """The comitter's signature"""

        def __get__(self):
            return build_person(git_commit_committer(self._commit()),
                self.repo)

    property author:
        """The author's signature"""

        def __get__(self):
            return build_person(git_commit_author(self._commit()), self.repo)

    property tree:
        """The tree pointed to by this commit."""

        def __get__(self):
            cdef int error
            cdef git_tree *tree
            cdef Tree py_tree

            error = git_commit_tree(&tree, self._commit())
            if error == git2.GIT_ENOTFOUND:
                return None
            else:
                err(error)

            py_tree = _new(Tree)
            py_tree.obj = <git_object*>tree
            py_tree.repo = self.repo

            return py_tree

cdef class Tree(GitObject):
    """Tree object"""

    cdef git_tree* _tree(self):
        return <git_tree*>self.obj

    cdef int _fix_index(self, long index) except? -5:
        cdef size_t len
        cdef long slen

        len = slen = git_tree_entrycount(<git_tree*>self.obj)
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
        return wrap_tree_entry(entry, self)

    cdef _getitem_by_name(self, name):
        cdef git_tree_entry *entry

        e_name = self.repo.encode(name)
        entry = git_tree_entry_byname(self._tree(), e_name)
        if entry is NULL:
            raise KeyError(name)
        return wrap_tree_entry(entry, self)

    def __getitem__(self, value):
        if isinstance(value, (bytes, unicode)):
            return self._getitem_by_name(value)
        elif isinstance(value, int):
            return self._getitem_by_index(value)
        else:
            raise TypeError("Tree entry index must be int or str, not %.200s" %
                type(value).__name__)

    def __iter__(self):
        return TreeIter.__new__(TreeIter, self)

    def __len__(self):
        assert self._tree()
        return git_tree_entrycount(self._tree())

    def __contains__(self, name):
        name = self.repo.encode(name)
        return git_tree_entry_byname(self._tree(), name) is not NULL

cdef class TreeIter(object):
    """Tree iterator"""

    cdef Tree owner
    cdef int i

    def __cinit__(self, owner):
        self.owner = owner
        self.i = 0

    def __init__(self):
        raise TypeError('This class cannot be instantiated directly')

    def __next__(self):
        cdef git_tree_entry *tree_entry

        tree_entry = git_tree_entry_byindex(self.owner._tree(), self.i)
        if tree_entry is NULL:
            raise StopIteration

        self.i += 1
        return wrap_tree_entry(tree_entry, self.owner)

cdef class Blob(GitObject):
    """Blob object"""

    property data:
        """This blob's raw data, as a byte string"""

        def __get__(self):
            return self.read_raw()

    property string:
        """This blob's data, as a string

        under Python 2, this is the same as data
        """

        def __get__(self):
            return self.repo.decode(self.data)

cdef class Tag(GitObject):
    """Tag object"""

    cdef _target

    cdef git_tag* _tag(self):
        return <git_tag*>self.obj

    property target:
        """The tagged object"""

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
        """This tag's name """

        def __get__(self):
            cdef char *name = git_tag_name(self._tag())
            if name is NULL:
                return None
            return self.repo.decode(name)

    property tagger:
        """The tagger's signature (name, e-mail, tagging time)"""

        def __get__(self):
            cdef git_signature *signature = git_tag_tagger(self._tag())
            if signature is NULL:
                return None
            return build_person(signature, self.repo)

    property message:
        """Message of this tag"""

        def __get__(self):
            cdef char *message = git_tag_message(self._tag())
            if message is NULL:
                return None
            return self.repo.decode(message)

cdef class Reference(object):
    """Reference
    """

    cdef git_reference *reference
    cdef Repository repo

    def __init__(self):
        raise TypeError('This class cannot be instantiated directly')

    property target:
        """Full name to the reference pointed by this reference

        Only available if the reference is symbolic
        """

        def __get__(self):
            cdef char *name

            name = git_reference_target(self.reference)
            if name is NULL:
                raise ValueError("Not target available")

            return self.repo.decode(name)

        def __set__(self, name):
            name = self.repo.encode(name)
            err(git_reference_set_target(self.reference, name))

    property name:
        """The full name of this reference."""
        def __get__(self):
            return self.repo.decode(git_reference_name(self.reference))

    property type:
        """Reference type (GIT_REF_OID, GIT_REF_SYMBOLIC or GIT_REF_PACKED).
        """

        def __get__(self):
            return git_reference_type(self.reference)

    property sha:
        """Hex SHA that the reference is pointing to.

        The SHA is only available for direct (i.e. not symbolic) references.
        """

        def __get__(self):
            cdef git_oid *oid

            oid = git_reference_oid(self.reference)
            if oid is NULL:
                raise ValueError(
                     "sha is only available if the reference is direct "
                     "(i.e. not symbolic)")

            return git_oid_to_py_str(oid)

        def __set__(self, sha):
            cdef git_oid oid

            py_str_to_git_oid(sha, &oid)

            err(git_reference_set_oid(self.reference, &oid))

    def rename(self, name):
        """Rename the reference.

        This method works for both direct and symbolic references.
        The new name will be checked for validity and may be modified into
        a normalized form.

        The refernece will be immediately renamed in-memory and on disk.
        """

        name = self.repo.encode(name)
        err(git_reference_rename(self.reference, name, 0))

    def resolve(self):
        """Resolve a symbolic reference and return a direct reference.

        This method iteratively peels a symbolic reference until it resolves
        to a direct reference to an actual object.

        If used on a direct reference, this reference is returned immediately.
        """
        cdef git_reference *c_reference

        err(git_reference_resolve(&c_reference, self.reference))

        return wrap_reference(c_reference, self.repo)

    def delete(self):
        """Delete this reference. It will no longer be valid!

        This reference will be immediately removed on disk and from memory.
        """

        err(git_reference_delete(self.reference))

        self.reference = NULL

cdef wrap_reference(git_reference *c_reference, Repository repo):
    """Internal factory function"""

    cdef Reference reference

    reference = _new(Reference)
    reference.reference = c_reference
    reference.repo = repo
    return reference

cdef class IndexEntry(object):
    """Index entry"""
    cdef git_index_entry *entry
    cdef Index index

    def __cinit__(self, index):
        self.index = index

    def __init__(self, index):
        raise TypeError('This class cannot be instantiated directly')

    property mode:
        """mode of this entry"""
        def __get__(self):
            return self.entry.mode

    property sha:
        def __get__(self):
            """SHA for this entry"""
            return git_oid_to_py_str(&self.entry.oid)

    property path:
        """filename of this entry"""
        def __get__(self):
            return self.index.repo.decode(self.entry.path)

cdef wrap_index_entry(git_index_entry *entry, index):
    """Internal factory function"""

    cdef IndexEntry py_entry

    py_entry = IndexEntry.__new__(IndexEntry, index)
    py_entry.entry = entry
    return py_entry

cdef class Index(object):
    """Index file

    Each Index object is independent and suffers no race conditions:
    synchronization is done at the FS level (using the `read` and `write`
    methods).
    """

    cdef git_index *index
    cdef Repository repo
    cdef int own_obj

    def __cinit__(self, path, repo=None):
        self.repo = repo
        self.own_obj = 0

    def __init__(self, path):
        """Open the given file as a bare index (not tied to a Repository)

        Since there is no ODB or working directory behind this index,
        any Index methods which rely on these (e.g. add) will fail with
        a GitError.

        If you need to access the index of an actual repository,
        use the Repository.index wrapper.
        """

        path = encode_path(path)

        err_str(path, git_index_open(&self.index, path))

        self.own_obj = 1

    def __del__(self):
        if self.own_obj:
            git_index_free(self.index)

    def __len__(self):
        return git_index_entrycount(self.index)

    def __getitem__(self, value):
        cdef int idx
        cdef git_index_entry *index_entry

        index_entry = git_index_get(self.index, self.get_position(value))
        if index_entry is NULL:
            raise KeyError(value)

        return wrap_index_entry(index_entry, self)

    def __setitem__(self, key, value):
        raise NotImplementedError("set item on index not yet implemented; "
            "use add() instead.")

    def __delitem__(self, key):
        err(git_index_remove(self.index, self.get_position(key)))

    def __contains__(self, path):
        cdef int idx

        path = self.repo.encode(path)
        idx = git_index_find(self.index, path)
        if idx == git2.GIT_ENOTFOUND:
            return False
        elif idx < 0:
            err_str(path, idx)
        else:
            return True

    def __iter__(self):
        return IndexIter.__new__(IndexIter, self)

    cdef int get_position(self, value) except? -5:
        """An internal method used by __getitem__ and __setitem__"""

        cdef int idx

        if isinstance(value, (bytes, unicode)):
            encoded_value = self.repo.encode(value)
            idx = git_index_find(self.index, encoded_value)
            if idx < 0:
                err_str(value, idx)
        elif isinstance(value, int):
            idx = value
            if idx < 0:
                raise ValueError(value)
        else:
            raise TypeError("Index entry key must be int or str, not %.200s" %
                     type(value).__name__)

        return idx

    def add(self, path, int stage=0):
        """Add or update an index entry from a file on disk.

        This method will fail on bare index instances.

        `path`:  Filename to add. The file must be relative to the Repository's
            working folder and must be readable.
        `stage`: Stage for the entry
        """

        # TODO: encode_path or self.repo.encode? The should be in sync...
        path = encode_path(path)
        err_str(path, git_index_add(self.index, path, stage))

    def read(self):
        """Update the contents of this Index in memory by reading from disk.
        """

        err(git_index_read(self.index))

    def write(self):
        """Write this Index from memory back to disk using an atomic file lock.
        """

        err(git_index_write(self.index))

    def clear(self):
        """Clear the contents (all the entries) of this Index.

        This clears the index object in memory; changes must be manually
        written to disk for them to take effect.
        """

        git_index_clear(self.index)

    def create_tree(self):
        """"Create a tree from the index file, return its SHA."

        This method will scan the index and write a representation of its
        current state back to disk; it recursively creates tree objects for
        each of the subtrees stored in the index, but only returns the SHA for
        the root tree. This is the SHA that can be used e.g. to create
        a commit.

        The Index cannot be bare, it needs to be associated to an existing
        repository.
        """

        cdef git_oid oid

        err(git_tree_create_fromindex(&oid, self.index))

        return git_oid_to_py_str(&oid)

cdef class IndexIter(object):
    """Index iterator
    """

    cdef Index owner
    cdef int i

    def __cinit__(self, owner):
        self.owner = owner
        self.i = 0

    def __init__(self):
        raise TypeError('This class cannot be instantiated directly')

    def __iter__(self):
        return self

    def __next__(self):
        cdef git_index_entry *index_entry

        index_entry = git_index_get(self.owner.index, self.i)
        if index_entry is NULL:
            raise StopIteration

        self.i += 1
        return wrap_index_entry(index_entry, self.owner)

cdef class Walker(object):
    """Revision walker
    """

    cdef git_revwalk *walk
    cdef Repository repo

    def __cinit__(self, repo):
        self.repo = repo

    def __init__(self):
        raise TypeError('This class cannot be instantiated directly')

    def __del__(self):
        git_revwalk_free(self.walk)

    def __next__(self):
        cdef git_oid oid
        cdef git_commit *commit
        cdef Commit py_commit

        err(git_revwalk_next(&oid, self.walk))

        err(git_commit_lookup(&commit, self.repo.repo, &oid))

        py_commit = _new(Commit)
        py_commit.obj = <git_object*>commit
        py_commit.repo = self.repo
        return py_commit

    def __iter__(self):
        return self

    def hide(self, sha):
        """Mark a commit (and its ancestors) uninteresting for the output.

        `sha`:  SHA of the commit that's to be hidden.
        """

        cdef git_oid oid

        py_str_to_git_oid(sha, &oid)

        err(git_revwalk_hide(self.walk, &oid))

    def push(self, sha):
        """Mark a commit to start traversal from.

        The given SHA must identify a commit on the walked repository.

        The given commit will be used as one of the roots when starting the
        revision walk.
        """

        cdef git_oid oid

        py_str_to_git_oid(sha, &oid)

        err(git_revwalk_push(self.walk, &oid))

    def  sort(self, int sort_mode):
        """Change the sorting mode (this resets the walker).
        """

        git_revwalk_sorting(self.walk, sort_mode)

    def reset(self):
        """Reset the walking machinery for reuse.

        This will clear all the pushed and hidden commits, and leave the walker
        in a blank state (just like at creation) ready to receive new commit
        pushes and start a new walk.

        The revision walk is automatically reset when a walk is over.
        """

        git_revwalk_reset(self.walk)

cdef class Repository(object):
    """Git repository

    A repository's `encoding` argument specifies the encoding for paths,
    messages, reference/tag/author names, etc. in the repository.

    In Python 2, `encoding` is None by default, which means that the Repository
    will give unencoded byte strings. In this case, unicode strings are
    accepted, and decoded using UTF-8.

    In Python 3, `encoding` is 'utf-8' by default. Setting it to None will
    cause the Repository to only accept raw byte strings.
    """

    cdef git_repository* repo
    cdef _index
    cdef str encoding

    def __cinit__(self, path=None):
        if py3:
            self.encoding = 'utf-8'
        else:
            self.encoding = None

    def __init__(self, path):
        path = encode_path(path)
        err_str(path, git_repository_open(&self.repo, path))

    def __del__(self):
        """Free the repo when we're done with it"""

        if self.repo:
            git_repository_free(self.repo)

    def __getitem__(self, value):
        """Get an object from the Repository by its SHA.
        """

        cdef git_oid oid

        py_str_to_git_oid(value, &oid)

        return self.lookup_object(&oid, GIT_OBJ_ANY)

    def __contains__(self, value):
        """Check if the object with the given SHA exists in the Repository.
        """

        cdef git_oid oid

        py_str_to_git_oid(value, &oid)
        return git_odb_exists(git_repository_database(self.repo), &oid)

    cdef encode(self, string):
        """Encode any string to a bytestring, honoring the `encoding` attribute
        """

        if isinstance(string, unicode):
            if self.encoding is None:
                if py3:
                    raise TypeError('This repository only accepts byte '
                        'strings')
                else:
                    return string.encode('utf-8')
            else:
                return string.encode(self.encoding)
        else:
            return string

    cdef decode(self, char *string):
        """Decode a C bytestring into some Python string, honoring `encoding`.

        """
        # TODO: Properly support other encodings than UTF-8? Does anyone care?

        if self.encoding is None:
            return string
        else:
            py_string = string
            return py_string.decode(self.encoding)

    cdef lookup_object(self, git_oid *oid, git_otype type):
        """Internal method used in __getitem__, etc."""

        cdef int error
        cdef char hex[git2.GIT_OID_HEXSZ + 1]
        cdef git_object *obj
        cdef int otype
        cdef GitObject py_obj

        error = git_object_lookup(&obj, self.repo, oid, type)
        if error < 0:
            git_oid_fmt(hex, oid)
            hex[git2.GIT_OID_HEXSZ] = '\0'
            err_str(hex, error)

        if obj is NULL:
            raise MemoryError()

        otype = git_object_type(obj)
        if otype == git2.GIT_OBJ_COMMIT:
            cls = Commit
        elif otype == git2.GIT_OBJ_TREE:
            cls = Tree
        elif otype == git2.GIT_OBJ_BLOB:
            cls = Blob
        elif otype == git2.GIT_OBJ_TAG:
            cls = Tag
        else:
            raise RuntimeError("Bad Git object type (%s)" % otype)

        py_obj = _new(cls)
        py_obj.obj = obj
        py_obj.repo = self
        return py_obj

    def status(self):
        """"Get the status of the repository as a dict.

        Returns a dictionary with file paths as keys and status flags as
        values.

        See pygit2.GIT_STATUS_* for the status flags.
        """

        payload_dict = {}
        payload = (payload_dict, self)
        git_status_foreach(self.repo, read_status_cb, <void*>payload)
        return payload_dict

    cpdef create_tag(self, tag_name, sha, git_otype target_type, tagger,
            message):
        """Create a new tag object, return its SHA.

        `tag_name`:  Name for the tag; this name is validated for consistency.
                It should also not conflict with an already existing tag name.
        `sha`:  SHA of the object to which this tag points. This object must
                belong to this Repository.
        `target_type`:  Type of the target object
        `tagger`:  Signature of the tagger for this tag, and of the tagging
                time
        `message`:  Full message for this tag
        """

        cdef git_oid c_oid
        cdef git_signature *c_tagger
        cdef git_object *target
        cdef char hex[git2.GIT_OID_HEXSZ + 1]

        tag_name = self.encode(tag_name)
        message = self.encode(message)

        py_str_to_git_oid(sha, &c_oid)
        signature_converter(tagger, &c_tagger, self)

        error = git_object_lookup(&target, self.repo, &c_oid, target_type)
        if error < 0:
            git_oid_fmt(hex, &c_oid)
            hex[git2.GIT_OID_HEXSZ] = '\0'
            err_str(hex, error)

        err = git_tag_create(&c_oid, self.repo, tag_name, target, c_tagger,
                message, 0)
        git_object_close(target)
        if err < 0:
            raise RuntimeError

        return git_oid_to_py_str(&c_oid)

    def walk(self, value, unsigned int sort):
        """Generator that traverses the history starting from the given commit.

        `value`:  SHA of the commit to start from.
            The given commit will be used as one of the roots when starting
            the revision walk.
            If None, at least one commit must be pushed to the walker later,
            before a walk can be started.
        `sort`:  Combination of GIT_SORT_XXX flags that specify the sorting
            mode when iterating through the repository's contents.
        """

        cdef git_revwalk *walk
        cdef Walker walker
        cdef git_oid oid

        if value is not None and not isinstance(value, (bytes, unicode)):
            raise TypeError(value)

        err(git_revwalk_new(&walk, self.repo))

        try:
            # Sort
            git_revwalk_sorting(walk, sort)

            # Push
            if value is not None:
                py_str_to_git_oid(value, &oid)
                err(git_revwalk_push(walk, &oid))

            walker = Walker.__new__(Walker, self)
            walker.walk = walk
            return walker

        except:
            git_revwalk_free(walk)
            raise

    cdef int read_raw(self, git_odb_object **obj, git_oid *oid):
        """Internal method to read an object's data into a git_odb_object*"""

        return git_odb_read(obj, git_repository_database(self.repo), oid)

    def read(self, sha):
        """Read raw object data from the repository, given an object's SHA.
        """

        cdef git_oid oid
        cdef git_odb_object *obj

        py_str_to_git_oid(sha, &oid)

        err_obj(sha, self.read_raw(&obj, &oid))

        length = git_odb_object_size(obj)
        retval = (git_odb_object_type(obj),
            (<char *>git_odb_object_data(obj))[:length])

        git_odb_object_close(obj)
        return retval

    def write(self, int type_id, data):
        """"Write raw object data into the repository.

        `type_id`:  The object type
        `data`: A string with data.

        Return the hexadecimal SHA of the created object.
        """
        cdef git_otype type
        cdef git_odb* odb
        cdef int error
        cdef git_odb_stream* stream
        cdef git_oid oid

        type = int_to_loose_object_type(type_id)
        if type == GIT_OBJ_BAD:
            raise GitError("Invalid object type")

        odb = git_repository_database(self.repo)

        if isinstance(data, unicode):
            data = self.encode(data)
        elif not isinstance(data, bytes):
            data = bytes(data)
        error = git_odb_open_wstream(&stream, odb, len(data), type)
        if error == git2.GIT_SUCCESS:
            stream.write(stream, data, len(data))
            error = stream.finalize_write(&oid, stream)
            stream.free(stream)
        err_str("failed to write data", error)

        return git_oid_to_py_str(&oid)

    property workdir:
        """The normalized path to the working directory of the repository.

        If the repository is bare, None will be returned.
        """

        def __get__(self):
            cdef char *c_path

            c_path = git_repository_path(self.repo, GIT_REPO_PATH_WORKDIR)
            if c_path is NULL:
                return None

            return decode_path(c_path)

    property path:
        """The normalized path to the git repository.
        """

        def __get__(self):
            cdef char *c_path

            c_path = git_repository_path(self.repo, GIT_REPO_PATH)
            if c_path is NULL:
                return None

            return decode_path(c_path)

    property index:
        """Index file.
        """

        def __get__(self):
            cdef int error
            cdef git_index *index
            cdef Index py_index

            assert self.repo

            if self._index is None:
                error = git_repository_index(&index, self.repo)
                if error == git2.GIT_SUCCESS:
                    py_index = Index.__new__(Index, None, repo=self)
                    py_index.index = index
                    self._index = py_index
                elif error == git2.GIT_EBAREINDEX:
                    self._index = False
                else:
                    err(error)

            return self._index or None

    property encoding:
        def __get__(self):
            return self.encoding

        def __set__(self, value):
            self.encoding = value

    def lookup_reference(self, name):
        """Lookup a reference by its name in this repository.
        """

        cdef git_reference *c_reference

        name = self.encode(name)
        err(git_reference_lookup(&c_reference, self.repo, name))

        return wrap_reference(c_reference, self)

    def create_reference(self, name, sha):
        """Create a new direct (object id) reference

        The reference will be created in the repository and written to the
        disk.

        `name`:  Name of the newly created reference
        `sha`:  SHA of the object to point the new reference to
        """
        cdef git_reference *c_reference
        cdef git_oid oid

        py_str_to_git_oid(sha, &oid)
        name = self.encode(name)

        err(git_reference_create_oid(&c_reference, self.repo, name, &oid, 0))

        return wrap_reference(c_reference, self)

    def create_symbolic_reference(self, name, target):
        """Create a new symbolic reference.

        The reference will be created in the repository and written to the
        disk.

        `name`:  Name of the newly created reference
        `target`:  Name of an existing reference that the new one will point to
        """

        cdef git_reference *reference

        name = self.encode(name)
        target = self.encode(target)
        err(git_reference_create_symbolic(&reference, self.repo, name,
                target, 0))

        return wrap_reference(reference, self)

    def packall_references(self):
        """Pack all the loose references in the repository.

        This method will load into the cache all the loose references on the
        repository and update the `packed-refs` file with them.

        Once the `packed-refs` file has been written properly, the loose
        references will be removed from disk.

        WARNING: calling this method may invalidate any existing references
        previously loaded on the cache.
        """

        err(git_reference_packall(self.repo))

    def listall_references(self, unsigned list_flags=GIT_REF_LISTALL):
        """Return a list with all the references in the repository.

        The listed references may be filtered by type, or using a bitwise OR
        of several types. Use the default value, `GIT_REF_LISTALL`, to obtain
        all references, including packed ones.
        """

        cdef git_strarray c_result
        cdef int index

        err(git_reference_listall(&c_result, self.repo, list_flags))

        try:
            result = []
            for index in range(c_result.count):
                result.append(decode_path(c_result.strings[index]))
            return tuple(result)
        finally:
            git_strarray_free(&c_result)

    def create_commit(self, update_ref, author, committer, message,
                tree, parent_list):
        """Create a new commit object, return its SHA.

        `update_ref`:  If not None, name of the reference that will be updated
            to point to this commit. If the reference is not direct, it will
            be resolved to a direct reference. Use "HEAD" to update the HEAD
            of the current branch and make it point to this commit
        `author`:  Signature representing the author and the authory time of
            this commit
        `committer`:  Signature representing the committer and the commit
            time of this commit
        `message`:  Full message for this commit
        `tree`:  SHA of a tree object that will be used as the tree for the
            commit. This tree object must be found in this Repository.
        `parent_list`:  List of SHAs of commits objects that will be used as
            the parents for this commit. All the given commits must be found in
            this Repository.
        """

        cdef char *c_update_ref = NULL
        cdef git_signature *c_author, *c_committer
        cdef git_oid oid
        cdef int i, last_parent = 0
        cdef git_commit **parents
        cdef git_tree *c_tree

        if update_ref is not None:
            c_update_ref = update_ref

        signature_converter(author, &c_author, self)
        signature_converter(committer, &c_committer, self)
        py_str_to_git_oid(tree, &oid)
        message = self.encode(message)

        err(git_tree_lookup(&c_tree, self.repo, &oid))

        try:

            mem_size = len(parent_list) * sizeof(git_commit*)
            parents = <git_commit**>malloc(mem_size)

            if parents is NULL:
                raise MemoryError

            try:
                for i, parent in enumerate(parent_list):
                    py_str_to_git_oid(parent, &oid)
                    if git_commit_lookup(&parents[i], self.repo, &oid):
                        raise RuntimeError
                    last_parent = i

                err(git_commit_create(&oid, self.repo, c_update_ref,
                        c_author, c_committer, NULL, message, c_tree,
                        len(parent_list), parents))

                return git_oid_to_py_str(&oid)

            finally:
                for j in range(last_parent + 1):
                    git_commit_close(parents[i])
                free(parents)

        finally:
            git_tree_close(c_tree)

def init_repository(path, bint bare=False):
    """Creates a new Git repository in the given directory.

    `path`:  The path to the repository
    `bare`:  If true, a Git repository without a working directory is created
        at the pointed path. If false (default), provided path will be
        considered as the working directory into which the .git directory will
        be created.
    """

    cdef git_repository *repo
    cdef Repository py_repo

    path = encode_path(path)

    err_str(path, git_repository_init(&repo, path, bare))
    try:
        py_repo = _new(Repository)
        py_repo.repo = repo
        return py_repo
    except:
        git_repository_free(repo)
        raise
