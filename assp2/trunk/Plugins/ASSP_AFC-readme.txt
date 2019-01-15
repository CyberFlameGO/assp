ATTENTION: 

Before you can use the ASSP_AFC plugin version - you have to:

- install at least assp.pl 2.6.2 build 18085
- configure 'UserAttach' using the 'file:...' option (eg.: file:files/userattachment.txt)

check that the following Perl modules are installed - which should be already the case

Archive::Zip
Archive::Extract
IO::Compress::Base
IO::Compress::Bzip2
IO::Compress::Deflate
IO::Compress::Gzip
IO::Compress::Lzma
IO::Compress::RawDeflate
IO::Compress::Xz
IO::Compress::Zip
Archive::Rar
Archive::Rar::Passthrough
Archive::Libarchive::XS
File::Type
OLE::Storage_Lite
Email::Outlook::Message
Crypt::SMIME


To support decompression for RAR formats you need to
- install Archive::Rar
- install a rar or unrar executable (already included in the ppm for windows)

To support decompression of various formats you need to 
- install Archive::Rar
- install a 7z or 7za or 7zip or p7zip executable (already included in the ppm for windows)

Version 5.xx supports corporate and privat SMIME signing and the RAR and 7z decompression.
The SMIME signing feature requires a nonpublic license! It is safe to leave the SMIME feature unconfigured.

The version 5.xx is available in the 'ASSP_AFC_V5_SMIME' folder.