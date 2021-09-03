#ifndef __KERNEL__

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#else

#include <asm/syscalls.h>
#include <linux/export.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vfs.h>
#define UINT64_MAX 18446744073709551615ULL

#endif

#include "function.h"
#include "zfile_ro_file.h"

const static uint64_t MAX_OFFSET = (1UL << 50) - 1;
const static uint32_t MAX_LENGTH = (1 << 14) - 1;
// const static uint64_t INVALID_OFFSET = MAX_OFFSET;
const static uint64_t INVALID_OFFSET = (1UL << 50) - 1;
const static uint32_t ALIGNMENT4K = 4 << 10;
// const static uint32_t ALIGNMENT      = 512U;
#define ALIGNMENT 512U
const static int MAX_LAYERS = 255;
const static int MAX_IO_SIZE = 4 * 1024 * 1024;


/* ========================= HeaderTrailer ============================= */
static const uint32_t FLAG_SHIFT_HEADER = 0; // 1:header     0:trailer
static const uint32_t FLAG_SHIFT_TYPE = 1;   // 1:data file, 0:index file
static const uint32_t FLAG_SHIFT_SEALED = 2; // 1:YES,       0:NO
static const uint32_t HT_SPACE = 4096;

struct _UUID {
  uint32_t a;
  uint16_t b, c, d;
  uint8_t e[6];
};

static uint64_t *MAGIC0 = (uint64_t *)"LSMT\0\1\2";

static struct _UUID MAGIC1 = {
    0xd2637e65, 0x4494, 0x4c08, 0xd2a2, {0xc8, 0xec, 0x4f, 0xcf, 0xae, 0x8a}};

struct zfile_ht {
  uint64_t magic0;
  struct _UUID magic1;
  // offset 24, 28
  uint32_t size;  //= sizeof(HeaderTrailer);
  uint32_t flags; //= 0;
  // offset 32, 40, 48
  uint64_t index_offset; // in bytes
  uint64_t index_size;   // # of SegmentMappings
  uint64_t virtual_size; // in bytes
} __attribute__((packed));

static uint32_t get_flag_bit(const struct zfile_ht *ht, uint32_t shift) {
  return ht->flags & (1 << shift);
}

static bool is_header(const struct zfile_ht *ht) {
  return get_flag_bit(ht, FLAG_SHIFT_HEADER);
}
static bool is_trailer(const struct zfile_ht *ht) { return !is_header(ht); }
static bool is_data_file(const struct zfile_ht *ht) {
  return get_flag_bit(ht, FLAG_SHIFT_TYPE);
}
static bool is_index_file(const struct zfile_ht *ht) {
  return !is_data_file(ht);
}
static bool is_sealed(const struct zfile_ht *ht) {
  return get_flag_bit(ht, FLAG_SHIFT_SEALED);
}
static bool verify_magic(const struct zfile_ht *ht) {
  return ht->magic0 == *MAGIC0 &&
         (memcmp(&ht->magic1, &MAGIC1, sizeof(MAGIC1)) == 0);
}

/* ========================= LSMTReadOnly File ============================= */

int set_max_io_size(struct zfile_file *file, size_t size) {
  if (size == 0 || (size & (ALIGNMENT4K - 1)) != 0) {
    PRINT_ERROR("size( %ld ) is not aligned with 4K.", size);
    return -1;
  }
  file->MAX_IO_SIZE = size;
  return 0;
}

size_t get_max_io_size(const struct zfile_file *file) {
  return file->MAX_IO_SIZE;
}

int do_build_jump_table( const uint32_t *ibuf, size_t n, off_t offset_begin) {
    
  size_t i;
  int part_size = DEFAULT_PART_SIZE;

  inttype local_min = 0;
  off_t raw_offset = offset_begin;

  struct jump_table* first_entry = (struct jump_table *)_zfile_malloc(
      sizeof(struct jump_table));
  first_entry.partial_offset = (raw_offset << lshift) + local_min;
  first_entry.deltas = 0;

  for (i = 1; i < (size_t) n + 1 ; ++i) {
	  raw_offset += ibuf[i - 1];
	  if (( i % part_size) == 0 ) {
		  local_min = inttype_max;
		  for (ssize_t j = i; j < MIN(n + 1, i + part_size ); j ++ )
			  local_min = MIN(ibuf[j - 1], local_min);
   		  struct jump_table* new_entry = (struct jump_table *)_zfile_malloc(
      			sizeof(struct jump_table));
  		  new_entry.partial_offset = (raw_offset << lshift) + local_min;
  		  new_entry.deltas = 0;              	             
		  continue;
	  }

  }
#ifndef __KERNEL__
  PRINT_ERROR("errno: %d, msg: %s", errno, strerror(errno));
#else
  PRINT_ERROR("ret is %d", ret);
#endif
  return NULL;
}

static bool do_load_jump_table(void *fd,
                               struct zfile_ht *pheader_tail,
			       struct jump_table *jump_table,
                                             bool trailer, ssize_t *n) {
  size_t jt_size = 0;
  struct zfile_ht *pht = NULL;
  ALIGNED_MEM(buf, HT_SPACE, ALIGNMENT4K);
  size_t file_size = 0;

  int ret = _zfile_pread(fd, buf, HT_SPACE, 0);

  if (ret < (ssize_t)HT_SPACE) {
    PRINT_ERROR("failed to read file header (fildes: %d).", *(int *)fd);
    goto error_ret;
  }

  pht = (struct zfile_ht *)buf;

  if (!verify_magic(pht) || !is_header(pht))
    goto error_ret;

  file_size = _zfile_get_file_size(fd);
  if (trailer) {
    size_t trailer_offset = file_size - HT_SPACE;
    if (!is_data_file(pht)) {
      PRINT_ERROR("uncognized file type (fildes: %d).", *(int *)fd);
      goto error_ret;
    }
    ret = _zfile_pread(fd, buf, HT_SPACE, trailer_offset);
    if (ret < (ssize_t)HT_SPACE) {
      PRINT_ERROR("failed to read file trailer "
                  "(fildes: %d).",
                  (int)(uint64_t)fd);
      goto error_ret;
    }
    if (!verify_magic(pht) || !is_trailer(pht) || !is_data_file(pht) ||
        !is_sealed(pht)) {
      PRINT_ERROR("trailer magic, trailer type, "
                  "file type or sealedness doesn't match"
                  " (fides: %d. %d)",
                  (int)(uint64_t)fd, is_trailer(pht));
      goto error_ret;
    }

    jt_size = pht->index_size * sizeof(unit32_t);
    PRINT_INFO("tailer offset: %d, idx_offset: %d, jt_size: %d, dict_size : %d "
                trailer_offset, pht->index_offset, jt_size, dict_size);

    if (jt_size > trailer_offset - pht->index_offset) {
      PRINT_ERROR("invalid index bytes or size "
                  "(fildes: %d).",
                  (int)(uint64_t)fd);
      goto error_ret;
    }
  }
#ifndef __KERNEL__
  posix_memalign((void **)&ibuf, ALIGNMENT4K, pht->index_size * sizeof(*ibuf));
#else
  ibuf = (struct segment_mapping *)kvmalloc(pht->index_size * sizeof(*ibuf),
                                            GFP_KERNEL);
#endif
  PRINT_INFO("index_offset: %d", pht->index_size);
  ret = _zfile_pread(fd, ibuf, index_bytes, pht->index_offset);
  //从file的 HeaderTrailer::SPACE 偏移开始读入indeVx
  if (ret < (ssize_t)index_bytes) {
    _zfile_free(ibuf);
    PRINT_ERROR("failed to read index (fildes: %d).", (int)(uint64_t)fd);
    goto error_ret;
  }
}

struct zfile_file *open_ro(void *fd, bool verify, bool ownership) {
  struct zfile_file *rst = NULL;
  struct zfile_ht ht;
  struct jump_table;
  ssize_t n = 0;
  size_t rst_size = 0;
  if (fd == NULL) {
    PRINT_ERROR("invalid file ptr. (fildes: %d)", (int)(uint64_t)fd);
    goto error_ret;
  }

  int retry = 2;
  again:
      if (!load_jump_table(file, &ht, jump_table, true))
      {
          if (verify && retry--) {
              // verify means the source can be evicted. evict and retry
              auto res = file->fallocate(0, 0, -1);
              PRINT_ERROR("failed load_jump_table, fallocate result: `", res);
              if (res < 0) {
                  PRINT_ERRNO(EIO, nullptr, "failed to read index for file: `, fallocate failed, no retry", file);
              }
              goto again;
          }
          PRINT_ERRNO(EIO, nullptr, "failed to read index for file: `", file);
      }

  if (!p) {
#ifndef __KERNEL__
    errno = EIO;
#endif
    PRINT_ERROR("failed to load index from file (fildes: %d).",
                (int)(uint64_t)fd);
    goto error_ret;
  }
  return rst;

error_ret:
  return NULL;
}

int close_file(struct zfile_file **file) {

  PRINT_INFO("destruct file. addr: %lu", (uint64_t)*file);
  if (*file == NULL)
    return 0;
  bool ok = true;
  if ((*file)->m_ownership) {
    int i;
    for (i = 0; i < (int)((*file)->m_files_count); i++) {
      if ((*file)->m_files[i] != NULL) {
#ifndef __KERNEL__
        int fd = (int)(uint64_t)((*file)->m_files[i]);
        PRINT_INFO("close file, fildes: %d", fd);
        if (close(fd) == 0)
          continue;
        PRINT_ERROR("close file error. (fildes: %d, "
                    "errno: %d, msg: %s",
                    fd, errno, strerror(errno));
#else
        struct file *filep = (struct file *)((*file)->m_files[i]);
        if (filp_close(filep, NULL) == 0)
          continue;
        PRINT_ERROR("close file error. ");
#endif
        ok = false;
      }
    }
  }
  if (!ok)
    return -1;
  PRINT_INFO("free memory. addr: %lu", (uint64_t)*file);
  _zfile_free(*file);
  *file = NULL;
  return 0;
}

static int merge_indexes(int level, struct zfile_ro_index **indexes, size_t n,
                         struct segment_mapping *mappings[], size_t *size,
                         size_t *capacity, uint64_t start, uint64_t end) {
  if (level >= n)
    return 0;
  PRINT_INFO("level %d range [ %lu, %lu ] %lu", level, start, end,
             ro_index_size(indexes[level]));
  struct segment_mapping *p =
      (struct segment_mapping *)ro_index_lower_bound(indexes[level], start);
  const struct segment_mapping *pend = indexes[level]->pend;
  if (p == pend) {
    merge_indexes(level + 1, indexes, n, mappings, size, capacity, start, end);
    return 0;
  }
  struct segment_mapping it = *p;
  if (start > it.offset) {
    forward_offset_to(&it, start, TYPE_SEGMENT_MAPPING);
  }

  while (p != pend) {
    if (end <= it.offset)
      break;
    if (start < it.offset) {
      merge_indexes(level + 1, indexes, n, mappings, size, capacity, start,
                    it.offset);
    }
    if (end < segment_end(&it)) {
      backward_end_to(&it, end);
    }
    if (*size == *capacity) {
      size_t tmp = (*capacity) << 1;
      PRINT_INFO("realloc array. ( %lu -> %lu )", *capacity, tmp);
#ifndef __KERNEL__
      struct segment_mapping *m = (struct segment_mapping *)realloc(
          *mappings, tmp * sizeof(struct segment_mapping));
      if (m == NULL) {
        PRINT_ERROR("realloc failed. errno: %d, msg: %s", errno,
                    strerror(errno));
        return -1;
      }
#else
      struct segment_mapping *m = (struct segment_mapping *)krealloc(
          *mappings, tmp * sizeof(struct segment_mapping), GFP_KERNEL);
      if (m == NULL) {
        PRINT_ERROR("realloc failed. ");
        return -1;
      }
#endif

      *mappings = m;
      *capacity = tmp;
    }

    it.tag = level;
    (*mappings)[*size] = it;
    (*size)++;
    start = segment_end(p);
    p++;
    it = *p;
  }
  if (start < end) {
    merge_indexes(level + 1, indexes, n, mappings, size, capacity, start, end);
  }
  return 0;
}

static struct zfile_ro_index *
merge_memory_indexes(struct zfile_ro_index **indexes, size_t n) {
  size_t size = 0;
  size_t capacity = ro_index_size(indexes[0]);
  struct zfile_ro_index *ret = NULL;
  struct segment_mapping *tmp = NULL;
  struct segment_mapping *mappings = (struct segment_mapping *)_zfile_malloc(
      sizeof(struct segment_mapping) * capacity);
  if (!mappings)
    goto err_ret;

  merge_indexes(0, indexes, n, &mappings, &size, &capacity, 0, UINT64_MAX);
  PRINT_INFO("merge done, index size: %lu", size);

  ret = (struct zfile_ro_index *)_zfile_malloc(sizeof(struct zfile_ro_index));
  tmp = (struct segment_mapping *)_zfile_realloc(
      mappings, size * sizeof(struct segment_mapping));

  if (!tmp || !ret)
    goto err_ret;
  ret->pbegin = tmp;
  ret->pend = tmp + size;
  PRINT_INFO("ret index done. size: %lu", size);
  return ret;

err_ret:
  _zfile_free(mappings);
  _zfile_free(ret);
  _zfile_free(tmp);
  return NULL;
}

static struct zfile_ro_index *load_merge_index(void **files, size_t n,
                                              struct zfile_ht *ht) {
  struct zfile_ro_index *indexes[MAX_LAYERS];
  struct zfile_ro_index *pmi = NULL;
  if (n > MAX_LAYERS) {
    PRINT_ERROR("too many indexes to merge, %d at most!", MAX_LAYERS);
    return NULL;
  }
  int i;
  for (i = 0; i < n; ++i) {
    ssize_t size = 0;
    struct segment_mapping *p = do_load_index(files[i], ht, true, &size);
    if (!p) {
      PRINT_ERROR("failed to load index from %d-th file", i);
#ifndef __KERNEL__
      errno = EIO;
#endif
      return NULL;
    }
    struct zfile_ro_index *pi =
        create_memory_index(p, ht->index_size, HT_SPACE / ALIGNMENT,
                            ht->index_offset / ALIGNMENT, false);
    if (!pi) {
      PRINT_ERROR("failed to create memory index! "
                  "( %d-th file )",
                  i);
      _zfile_free(p);
      return NULL;
    }
    indexes[i] = pi;
  }

  REVERSE_LIST(int, (int *)&files[0], (int *)&files[n - 1]);
  REVERSE_LIST(struct zfile_ro_index *, &indexes[0], &indexes[n - 1]);

  pmi = merge_memory_indexes(&indexes[0], n);

  if (!pmi) {
    PRINT_ERROR("failed to merge indexes %s", "");
    goto error_ret;
  }
  return pmi;

error_ret:
  return NULL;
}

size_t zfile_pread(struct zfile_file *file, void *buf, size_t nbytes,
                  off_t offset) {

  size_t readn = 0;
  int NMAPPING = 16;
  char *data = (char *)buf;
  struct segment_mapping mapping[NMAPPING];
  if ((nbytes | offset) & (ALIGNMENT - 1)) {
    PRINT_ERROR("count(%lu) and offset(%lu) must be aligned", nbytes, offset);
    // exit(0);
    return -1;
  }
  while (nbytes > file->MAX_IO_SIZE) {
    size_t read = zfile_pread(file, data, file->MAX_IO_SIZE, offset);
    if (read < file->MAX_IO_SIZE) {
      PRINT_ERROR("read data error: (return %lu < %lu )", read,
                  file->MAX_IO_SIZE);
      return -1;
    }
    data += read;
    offset += read;
    nbytes -= read;
    readn += read;
  }

  struct segment s = {(uint64_t)offset / ALIGNMENT,
                      (uint32_t)nbytes / ALIGNMENT};

  while (true) {
    int n = ro_index_lookup(file->m_index, &s, mapping, NMAPPING);
    int i;
    for (i = 0; i < n; i++) {
      if (s.offset < mapping[i].offset) {
        size_t length = (mapping[i].offset - s.offset) * ALIGNMENT;
        memset((void *)data, 0, length);
        data += length;
        readn += length;
      }
      void *fd = file->m_files[mapping[i].tag];
      ssize_t size = mapping[i].length * ALIGNMENT;
      ssize_t read = 0;
      if (mapping[i].zeroed == 0) {
        read = _zfile_pread(fd, data, size, mapping[i].moffset * ALIGNMENT);
        if (read < size) {
#ifndef __KERNEL__
          PRINT_ERROR("read %d-th file error."
                      "(%ld < %ld) errno: %d msg: %s",
                      mapping[i].tag, read, size, errno, strerror(errno));
#else
          PRINT_ERROR("read %d-th file error."
                      "(%ld < %ld) Read is %d",
                      mapping[i].tag, read, size, read);
#endif
          return -1;
        }
      } else {
        read = size;
        memset(data, 0, size);
      }
      readn += read;
      data += size;
      forward_offset_to(&s, segment_end(&mapping[i]), TYPE_SEGMENT);
    }
    if (n < NMAPPING)
      break;
  }
  if (s.length > 0) {
    size_t length = s.length * ALIGNMENT;
    memset(data, 0, length);
    data += length;
    readn += length;
  }
  return readn;
}

struct zfile_file *open_files(void **files, size_t n, bool ownership) {
  struct zfile_file *ret = (struct zfile_file *)_zfile_malloc(
      sizeof(files[0]) * n + sizeof(struct zfile_file));

  struct zfile_ht ht;
  struct zfile_ro_index *idx = load_merge_index(files, n, &ht);
  if (idx == NULL) {
    return NULL;
  }
  ret->m_files_count = n;
  ret->m_index = idx;
  ret->m_ownership = ownership;
  ret->m_vsize = ht.virtual_size;
  ret->MAX_IO_SIZE = MAX_IO_SIZE;
  memcpy(ret->m_files, &files[0], n * sizeof(files[0]));
  return ret;
}
