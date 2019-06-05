#	retools - Reverse engineering toolkit
#	Copyright (C) 2019-2019 Johannes Bauer
#
#	This file is part of retools.
#
#	retools is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	retools is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with retools; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import collections
import zlib
import enum
import struct
import os
import contextlib
from retools.NamedStruct import NamedStruct

class _InodeType(enum.IntEnum):
	Fifo = 1
	CharDev = 2
	Dir = 4
	BlockDev = 6
	RegularFile = 8
	Link = 10
	Socket = 12

class UncramFS():
	_Header = NamedStruct([
		("L", "magic"),
		("L", "size"),
		("L", "flags"),
		("L", "future"),
		("16s", "signature"),
		("L", "fsid_crc"),
		("L", "fsid_edition"),
		("L", "fsid_blocks"),
		("L", "fsid_files"),
		("16s", "name"),
	])

	_Inode = NamedStruct([
		("L", "mode_uid"),
		("L", "size_gid"),
		("L", "namelen_offset"),
	])

	_DecodedInode = collections.namedtuple("DecodedInode", [ "index", "at", "inodetype", "perms", "uid", "gid", "size", "offset", "filename", "nblocks" ])

	def __init__(self, f):
		self._f = f
		self._f.seek(0)
		self._hdr = self._Header.unpack_from_file(self._f)
		assert(self._hdr.magic == 0x28cd3d45)
		self._inodes = self._read_all_inodes()
		self._inode_index = { inode.at: inode.index for inode in self._inodes }

	def dump(self):
		for inode in self._inodes:
			print(inode)

	def _seek_root(self):
		self._f.seek(self._Header.size)

	def _read_next_inode(self, inode_index):
		at = self._f.tell()
		inode = self._Inode.unpack_from_file(self._f)
		mode = (inode.mode_uid >> 0) & 0xffff
		blocksize = 4096
		args = {
			"index":		inode_index,
			"at":			at,
			"inodetype":	_InodeType(mode >> 12),
			"perms":		mode & 0o7777,
			"uid":			(inode.mode_uid >> 16) & 0xffff,
			"size":			(inode.size_gid >> 0) & 0xffffff,
			"gid":			(inode.size_gid >> 24) & 0xff,
			"offset":		4 * ((inode.namelen_offset >> 6) & 0x3ffffff),
		}
		namelen = 4 * ((inode.namelen_offset >> 0) & 0x3f)
		filename = self._f.read(namelen).rstrip(b"\x00")
		args["filename"] = filename.decode("utf-8")
		args["nblocks"] = (args["size"] - 1) // blocksize + 1

		decoded_inode = self._DecodedInode(**args)
		return decoded_inode

	def _read_all_inodes(self):
		self._seek_root()
		inodes = [ self._read_next_inode(index) for index in range(self._hdr.fsid_files) ]
		return inodes

	def get_inode(self, inode_offset):
		index = self._inode_index[inode_offset]
		return self._inodes[index]

	def _listdir(self, inode_offset):
		root_inode = self.get_inode(inode_offset)
		if root_inode.inodetype != _InodeType.Dir:
			raise Exception("Inode at offset %d is not a directory (%s)." % (inode_offset, str(root_inode)))

		contained_files = [ ]
		contained_dirs = [ ]

		if root_inode.offset != 0:
			index = self.get_inode(root_inode.offset).index
			end = root_inode.offset + root_inode.size
			while True:
				next_inode = self._inodes[index]
				if next_inode.at >= end:
					break
				if next_inode.inodetype == _InodeType.Dir:
					contained_dirs.append(next_inode)
				else:
					contained_files.append(next_inode)
				index += 1
				if index >= len(self._inodes):
					break

		return (contained_files, contained_dirs)

	def _walk(self, pathname, inode_offset):
		(contained_files, contained_dirs) = self._listdir(inode_offset)
		yield (pathname, contained_files, contained_dirs)
		if not pathname.endswith("/"):
			pathname += "/"
		for subdir in contained_dirs:
			yield from self._walk(pathname + subdir.filename + "/", subdir.at)

	def walk(self):
		inode_offset = self._Header.size
		yield from self._walk("/", inode_offset)

	def walk_files(self):
		for (base_path, contained_files, contained_dirs) in self.walk():
			for file_inode in contained_files:
				full_filename = base_path + file_inode.filename
				yield (full_filename, file_inode)

	def retrieve_chunked_file(self, inode):
		self._f.seek(inode.offset)
		pointer_data = self._f.read(4 * inode.nblocks)
		pointers = struct.unpack("<%dL" % (inode.nblocks), pointer_data)

		offset = self._f.tell()
		for pointer in pointers:
			next_chunk_length = pointer - offset
			next_chunk = self._f.read(next_chunk_length)
			yield zlib.decompress(next_chunk)
			offset = pointer

	def retrieve_file(self, inode):
		result = bytearray()
		for chunk in self.retrieve_chunked_file(inode):
			result += chunk
		return result

	def uncram(self, target_directory):
		for (filename, inode) in self.walk_files():
			disk_file = target_directory + filename
			with contextlib.suppress(FileExistsError):
				os.makedirs(os.path.dirname(disk_file))
			with open(disk_file, "wb") as f:
				for chunk in self.retrieve_chunked_file(inode):
					f.write(chunk)

if __name__ == "__main__":
	with open("cramfs.img", "rb") as f:
		ucfs = UncramFS(f)
		ucfs.uncram("output_cram")
