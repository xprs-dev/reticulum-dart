/// Web default: a private in-memory tree. The host replaces it with its own
/// persisted tree at boot; until then nothing written here survives a reload,
/// which is the honest default for a package that cannot know where the host
/// keeps its files.
library;

import 'package:file/file.dart';
import 'package:file/memory.dart';

final FileSystem defaultFileSystem = MemoryFileSystem(style: FileSystemStyle.posix);
