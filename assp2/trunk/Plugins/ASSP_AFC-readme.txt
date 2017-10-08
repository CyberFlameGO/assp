ATTENTION: 

Before you can use the ASSP_AFC plugin version 3.xx - you have to:

- install the Perl module File::Type
- install the Perl module IO::Compress:Lzma
- install at least assp.pl 2.3.3 or 2.3.4 build 13302
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


In addition to wersion 3.xx - before you can use the ASSP_AFC plugin version 4.xx - you have to:

- install the Perl module Crypt::SMIME
- install at least assp.pl 2.4.5 or 2.4.6 build 15264

To support decompression for RAR formats you need to
- install Archive::Rar
- install a rar or unrar executable (already included in the ppm for windows)

To support decompression of various formats you need to 
- install Archive::Rar
- install a 7z or 7za or 7zip or p7zip executable (already included in the ppm for windows)

The available version 3.xx and 4.xx are identical versions, except that version 4.xx supports
corporate and privat SMIME signing and the RAR and 7z decompression.
The SMIME signing feature requires a nonpublic license! It is safe to use version 4.xx and to leave
the SMIME feature unconfigured.

The version 4.xx is available in the 'ASSP_AFC_V4_SMIME' folder.