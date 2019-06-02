# retools
When doing reverse engineering, I find myself coding and re-coding the same
tools over and over again. For a task at hand I now want to consolidate and
re-write those tools into a reusable package. Examples of functions it provides
(not all of which are rewritten yet, i.e., some are missing) are:

	* Recursively unpacking compressed images (e.g., a initrd image that
	  contains multiple compressed payloads)
	* Finding magic values (e.g., in binary analysis find code offsets that
	  contains AES lookup tables or SHA256 intialization constants or Elliptic
      Curve domain parameters) 
	* Finding specified values or strings (especially when you do not know
	  endianness or word length or string encoding such as UTF-8/UTF-16)
	* Patching binary code with "fuzzy" matching, i.e., hunks

## License
GNU GPL-3.
