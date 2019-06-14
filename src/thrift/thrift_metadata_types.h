/**
 * Autogenerated by Thrift Compiler (0.11.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef THRIFT_METADATA_TYPES_H
#define THRIFT_METADATA_TYPES_H

/* base includes */
#include <glib-object.h>
#include <thrift/c_glib/thrift_struct.h>
#include <thrift/c_glib/protocol/thrift_protocol.h>

/* custom thrift includes */

/* begin types */

enum _ThriftFileSystemModel {
  THRIFT_FILE_SYSTEM_MODEL_PASTIS = 0,
  THRIFT_FILE_SYSTEM_MODEL_BASIC = 1,
  THRIFT_FILE_SYSTEM_MODEL_SNAPSHOT = 2
};
typedef enum _ThriftFileSystemModel ThriftFileSystemModel;

/* return the name of the constant */
const char *
toString_FileSystemModel(int value); 

enum _ThriftInodeType {
  THRIFT_INODE_TYPE_FILE = 0,
  THRIFT_INODE_TYPE_DIRECTORY = 1,
  THRIFT_INODE_TYPE_SYMLINK = 2
};
typedef enum _ThriftInodeType ThriftInodeType;

/* return the name of the constant */
const char *
toString_InodeType(int value); 

enum _ThriftInodeFlags {
  THRIFT_INODE_FLAGS_EXECUTABLE = 1
};
typedef enum _ThriftInodeFlags ThriftInodeFlags;

/* return the name of the constant */
const char *
toString_InodeFlags(int value); 

enum _ThriftDirEntryDiffType {
  THRIFT_DIR_ENTRY_DIFF_TYPE_ADD = 0,
  THRIFT_DIR_ENTRY_DIFF_TYPE_REMOVE = 1
};
typedef enum _ThriftDirEntryDiffType ThriftDirEntryDiffType;

/* return the name of the constant */
const char *
toString_DirEntryDiffType(int value); 

/* struct FileSystem */
struct _ThriftFileSystem
{ 
  ThriftStruct parent; 

  /* public */
  gchar * name;
  gint32 block_size;
  gint64 root;
  gint64 inception;
  ThriftFileSystemModel model;
  gboolean __isset_model;
};
typedef struct _ThriftFileSystem ThriftFileSystem;

struct _ThriftFileSystemClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftFileSystemClass ThriftFileSystemClass;

GType thrift_file_system_get_type (void);
#define THRIFT_TYPE_FILE_SYSTEM (thrift_file_system_get_type())
#define THRIFT_FILE_SYSTEM(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_FILE_SYSTEM, ThriftFileSystem))
#define THRIFT_FILE_SYSTEM_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_FILE_SYSTEM, ThriftFileSystemClass))
#define THRIFT_IS_FILE_SYSTEM(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_FILE_SYSTEM))
#define THRIFT_IS_FILE_SYSTEM_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_FILE_SYSTEM))
#define THRIFT_FILE_SYSTEM_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_FILE_SYSTEM, ThriftFileSystemClass))

/* struct FileData */
struct _ThriftFileData
{ 
  ThriftStruct parent; 

  /* public */
  gint64 size;
  GPtrArray * blocks;
  gboolean __isset_blocks;
  GPtrArray * indirect;
  gboolean __isset_indirect;
};
typedef struct _ThriftFileData ThriftFileData;

struct _ThriftFileDataClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftFileDataClass ThriftFileDataClass;

GType thrift_file_data_get_type (void);
#define THRIFT_TYPE_FILE_DATA (thrift_file_data_get_type())
#define THRIFT_FILE_DATA(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_FILE_DATA, ThriftFileData))
#define THRIFT_FILE_DATA_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_FILE_DATA, ThriftFileDataClass))
#define THRIFT_IS_FILE_DATA(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_FILE_DATA))
#define THRIFT_IS_FILE_DATA_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_FILE_DATA))
#define THRIFT_FILE_DATA_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_FILE_DATA, ThriftFileDataClass))

/* struct FileDataIndirect */
struct _ThriftFileDataIndirect
{ 
  ThriftStruct parent; 

  /* public */
  GPtrArray * blocks;
  gboolean valid;
  gboolean __isset_valid;
};
typedef struct _ThriftFileDataIndirect ThriftFileDataIndirect;

struct _ThriftFileDataIndirectClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftFileDataIndirectClass ThriftFileDataIndirectClass;

GType thrift_file_data_indirect_get_type (void);
#define THRIFT_TYPE_FILE_DATA_INDIRECT (thrift_file_data_indirect_get_type())
#define THRIFT_FILE_DATA_INDIRECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_FILE_DATA_INDIRECT, ThriftFileDataIndirect))
#define THRIFT_FILE_DATA_INDIRECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_FILE_DATA_INDIRECT, ThriftFileDataIndirectClass))
#define THRIFT_IS_FILE_DATA_INDIRECT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_FILE_DATA_INDIRECT))
#define THRIFT_IS_FILE_DATA_INDIRECT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_FILE_DATA_INDIRECT))
#define THRIFT_FILE_DATA_INDIRECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_FILE_DATA_INDIRECT, ThriftFileDataIndirectClass))

/* struct DirEntry */
struct _ThriftDirEntry
{ 
  ThriftStruct parent; 

  /* public */
  gint64 inumber;
  ThriftInodeType type;
};
typedef struct _ThriftDirEntry ThriftDirEntry;

struct _ThriftDirEntryClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftDirEntryClass ThriftDirEntryClass;

GType thrift_dir_entry_get_type (void);
#define THRIFT_TYPE_DIR_ENTRY (thrift_dir_entry_get_type())
#define THRIFT_DIR_ENTRY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_DIR_ENTRY, ThriftDirEntry))
#define THRIFT_DIR_ENTRY_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_DIR_ENTRY, ThriftDirEntryClass))
#define THRIFT_IS_DIR_ENTRY(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_DIR_ENTRY))
#define THRIFT_IS_DIR_ENTRY_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_DIR_ENTRY))
#define THRIFT_DIR_ENTRY_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_DIR_ENTRY, ThriftDirEntryClass))

/* struct DirEntryDiff */
struct _ThriftDirEntryDiff
{ 
  ThriftStruct parent; 

  /* public */
  ThriftDirEntryDiffType diff_type;
  ThriftDirEntry * entry;
  gint64 mtime;
  gchar * name;
};
typedef struct _ThriftDirEntryDiff ThriftDirEntryDiff;

struct _ThriftDirEntryDiffClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftDirEntryDiffClass ThriftDirEntryDiffClass;

GType thrift_dir_entry_diff_get_type (void);
#define THRIFT_TYPE_DIR_ENTRY_DIFF (thrift_dir_entry_diff_get_type())
#define THRIFT_DIR_ENTRY_DIFF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_DIR_ENTRY_DIFF, ThriftDirEntryDiff))
#define THRIFT_DIR_ENTRY_DIFF_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_DIR_ENTRY_DIFF, ThriftDirEntryDiffClass))
#define THRIFT_IS_DIR_ENTRY_DIFF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_DIR_ENTRY_DIFF))
#define THRIFT_IS_DIR_ENTRY_DIFF_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_DIR_ENTRY_DIFF))
#define THRIFT_DIR_ENTRY_DIFF_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_DIR_ENTRY_DIFF, ThriftDirEntryDiffClass))

/* struct DirData */
struct _ThriftDirData
{ 
  ThriftStruct parent; 

  /* public */
  GHashTable * entries;
  gboolean __isset_entries;
  gint64 count;
  gboolean __isset_count;
  GByteArray * indirect;
  gboolean __isset_indirect;
};
typedef struct _ThriftDirData ThriftDirData;

struct _ThriftDirDataClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftDirDataClass ThriftDirDataClass;

GType thrift_dir_data_get_type (void);
#define THRIFT_TYPE_DIR_DATA (thrift_dir_data_get_type())
#define THRIFT_DIR_DATA(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_DIR_DATA, ThriftDirData))
#define THRIFT_DIR_DATA_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_DIR_DATA, ThriftDirDataClass))
#define THRIFT_IS_DIR_DATA(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_DIR_DATA))
#define THRIFT_IS_DIR_DATA_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_DIR_DATA))
#define THRIFT_DIR_DATA_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_DIR_DATA, ThriftDirDataClass))

/* struct DirDataIndirect */
struct _ThriftDirDataIndirect
{ 
  ThriftStruct parent; 

  /* public */
  GHashTable * entries;
  gboolean __isset_entries;
  gboolean valid;
  gboolean __isset_valid;
};
typedef struct _ThriftDirDataIndirect ThriftDirDataIndirect;

struct _ThriftDirDataIndirectClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftDirDataIndirectClass ThriftDirDataIndirectClass;

GType thrift_dir_data_indirect_get_type (void);
#define THRIFT_TYPE_DIR_DATA_INDIRECT (thrift_dir_data_indirect_get_type())
#define THRIFT_DIR_DATA_INDIRECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_DIR_DATA_INDIRECT, ThriftDirDataIndirect))
#define THRIFT_DIR_DATA_INDIRECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_DIR_DATA_INDIRECT, ThriftDirDataIndirectClass))
#define THRIFT_IS_DIR_DATA_INDIRECT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_DIR_DATA_INDIRECT))
#define THRIFT_IS_DIR_DATA_INDIRECT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_DIR_DATA_INDIRECT))
#define THRIFT_DIR_DATA_INDIRECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_DIR_DATA_INDIRECT, ThriftDirDataIndirectClass))

/* struct SymLinkData */
struct _ThriftSymLinkData
{ 
  ThriftStruct parent; 

  /* public */
  gchar * target;
};
typedef struct _ThriftSymLinkData ThriftSymLinkData;

struct _ThriftSymLinkDataClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftSymLinkDataClass ThriftSymLinkDataClass;

GType thrift_sym_link_data_get_type (void);
#define THRIFT_TYPE_SYM_LINK_DATA (thrift_sym_link_data_get_type())
#define THRIFT_SYM_LINK_DATA(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_SYM_LINK_DATA, ThriftSymLinkData))
#define THRIFT_SYM_LINK_DATA_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_SYM_LINK_DATA, ThriftSymLinkDataClass))
#define THRIFT_IS_SYM_LINK_DATA(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_SYM_LINK_DATA))
#define THRIFT_IS_SYM_LINK_DATA_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_SYM_LINK_DATA))
#define THRIFT_SYM_LINK_DATA_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_SYM_LINK_DATA, ThriftSymLinkDataClass))

/* struct Inode */
struct _ThriftInode
{ 
  ThriftStruct parent; 

  /* public */
  gint64 id;
  gint64 inumber;
  ThriftInodeType type;
  gint64 mtime;
  gint32 flags;
  ThriftFileData * file_data;
  gboolean __isset_file_data;
  ThriftDirData * directory_data;
  gboolean __isset_directory_data;
  ThriftSymLinkData * symlink_data;
  gboolean __isset_symlink_data;
};
typedef struct _ThriftInode ThriftInode;

struct _ThriftInodeClass
{
  ThriftStructClass parent;
};
typedef struct _ThriftInodeClass ThriftInodeClass;

GType thrift_inode_get_type (void);
#define THRIFT_TYPE_INODE (thrift_inode_get_type())
#define THRIFT_INODE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), THRIFT_TYPE_INODE, ThriftInode))
#define THRIFT_INODE_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), THRIFT__TYPE_INODE, ThriftInodeClass))
#define THRIFT_IS_INODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), THRIFT_TYPE_INODE))
#define THRIFT_IS_INODE_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), THRIFT_TYPE_INODE))
#define THRIFT_INODE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), THRIFT_TYPE_INODE, ThriftInodeClass))

/* constants */

#endif /* THRIFT_METADATA_TYPES_H */