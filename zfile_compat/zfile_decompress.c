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
#include <fcntl.h>
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
#include "lz4.h"

const static int MAX_OFFSET = (1UL << 50) - 1;
const static uint32_t MAX_LENGTH = (1 << 14) - 1;
// const static int INVALID_OFFSET = MAX_OFFSET;
const static int INVALID_OFFSET = (1UL << 50) - 1;
const static uint32_t ALIGNMENT4K = 4 << 10;
// const static uint32_t ALIGNMENT      = 512U;
#define ALIGNMENT 512U
const static int MAX_LAYERS = 255;
const static int MAX_IO_SIZE = 4 * 1024 * 1024;


/* ========================= HeaderTrailer ============================= */
/*
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
} */
static bool verify_magic(const struct zfile_ht *ht) {
  return ht->magic0 == *MAGIC0 &&
         (memcmp(&ht->magic1, &MAGIC1, sizeof(MAGIC1)) == 0);
}

/* ========================= ZFileReadOnly File ============================= */

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

size_t get_range ( size_t idx, uint64_t partial_offset[], uint16_t deltas[]) {

                 // return BASE  + idx % (page_size) * local_minimum + sum(delta - local_minimum)
     off_t part_idx = idx / DEFAULT_PART_SIZE;
     off_t inner_idx = idx & (DEFAULT_PART_SIZE - 1);
     uint16_t local_min = partial_offset[part_idx] & ((1 << DEFAULT_LSHIFT) - 1);
     uint64_t part_offset = partial_offset[part_idx] >> DEFAULT_LSHIFT;
     off_t ret = part_offset + deltas[idx] + (inner_idx)*local_min;
     return ret;

}

int get_blocks_length( size_t begin, size_t end, uint64_t partial_offset[], uint16_t deltas[]) {
    return (get_range( end, partial_offset, deltas) - get_range( begin, partial_offset, deltas));
}

int read_blocks(struct zfile_ht* pht, int src,  unsigned char *dst_buf, uint64_t partial_offset[], uint16_t deltas[], size_t begin, size_t end)
{
    
    size_t begin_offset = get_range( begin, partial_offset, deltas);
    size_t read_size = end - begin ;
    PRINT_INFO("block idx: [%d, %d], start_offset: %d, read_size: %d",
              begin, end, begin_offset, read_size);

    unsigned char src_buf[read_size * 2];
    size_t ret = pread(src, src_buf, read_size, begin_offset);
    PRINT_INFO("Tesla testing %ld", begin_offset);
    if (ret < (ssize_t)read_size) {
      PRINT_ERROR("failed to read file header (fildes: %d).", src);
      return 0;
    }

    unsigned char raw[MAX_READ_SIZE];
    size_t readn = 0;
    uint32_t src_blk_size = pht->opt.block_size;
    uint32_t max_dst_size = LZ4_compressBound(src_blk_size);
    uint32_t total_size = begin_offset + read_size;

	PRINT_INFO("it: [ %d], total_size: %d, read_size: %d",
               total_size, read_size);;

      if (( total_size ) > pht->opt.block_size)  {
    	PRINT_INFO("total_size_offset: %d",
               total_size);
	int dret = LZ4_decompress_safe(src_buf, (unsigned char *)dst_buf, pht->opt.block_size, max_dst_size); 
    	PRINT_INFO("it: [ %d], total_size_offset: %d",
               total_size);
        if (dret == -1)
            return -1;
	readn += pht->opt.block_size ;
	//dst_f = (unsigned char *) dst_buf + pht->opt.block_size;
      }  else {
    	PRINT_INFO(" total_sset: %d",
               total_size);
	int dret = LZ4_decompress_safe( src_buf, raw, total_size , max_dst_size); 
        if (dret == -1)
            return -1;
        memcpy(dst_buf, raw , total_size );
	readn += total_size;
	//dst_buf = (unsigned char *) dst_buf + pht->opt.block_size;
      }
    

    return readn;
}

int do_build_jump_table( int src, const uint32_t *ibuf, struct zfile_ht* pht, int dst) {
    
  size_t i;
  int part_size = DEFAULT_PART_SIZE;
  off_t offset_begin = pht->opt.dict_size + ZF_SPACE;
  size_t n = pht->index_size;
  PRINT_INFO("part_size:  %d, size:  %d, offset_begine: %d " , part_size, n, offset_begin );

  inttype local_min = 0;
  off_t raw_offset = offset_begin;
  uint16_t lshift = DEFAULT_LSHIFT;
  uint16_t last_delta;

  uint64_t partial_offset[ (size_t) n+1 ];
  uint16_t deltas[UINT16_MAX];
  uint16_t pushed_delta = 0; 

  for (i = 1; i < (size_t) n + 1 ; ++i) {
	  //PRINT_INFO(" ibuf %d", ibuf[i-1]);
	  raw_offset += ibuf[i - 1];
	  last_delta = 0;
	  //PRINT_INFO(" raw_offset %d", raw_offset);
	  if (( i % part_size) == 0 ) {
		  local_min = inttype_max;
		  for (ssize_t j = i; j < min(n + 1, i + part_size ); j ++ )
			  local_min = min(ibuf[j - 1], local_min);
   		  struct jump_table* new_entry = (struct jump_table *)_zfile_malloc(
      			sizeof(struct jump_table));
  		  partial_offset[i % part_size]  = (raw_offset << lshift) + local_min;
		  deltas[pushed_delta++] = 0;              	             
		  last_delta = 0;
		  PRINT_INFO( "partial_offset : %d ", new_entry->partial_offset );

		  continue;
	  }

	  last_delta = last_delta + ibuf[i-1] - local_min;

	  PRINT_INFO("last_delta %d, iterated %i", last_delta, i);
	 
  }

  size_t raw_data_size = pht->raw_data_size;
  size_t block_size = pht->opt.block_size;

  off_t read_size = (off_t) MAX_READ_SIZE;
  unsigned char buf[MAX_READ_SIZE];
  for (off_t offset = 0; offset < raw_data_size ; offset += read_size) {
	size_t len = min(block_size, (size_t)raw_data_size - offset);
        size_t readn = read_blocks(pht, src, buf, partial_offset, deltas, offset, offset + len );
	if (readn <= 0) {
		PRINT_ERROR("decompreassion failed , readn %d", readn);
	} else {
		write(dst, buf, len);
	}
  }  
  PRINT_INFO("DONE, check the result file", dst);
  return 0;
}

static bool do_load_jump_table(int src, int dst, 
                               struct zfile_ht *pheader_tail,
			       struct jump_table *jump_table,
                               bool trailer) {
  size_t jt_size = 0;
  struct zfile_ht buf[ZF_SPACE];//= NULL;
  //ALIGNED_MEM(buf, ZF_SPACE, ALIGNMENT4K);
  size_t file_size = 0;

//  PRINT_INFO("get  %s %s " ,src, dst );


  //char *buf  = (char *)calloc(ZF_SPACE, sizeof(char));
  size_t ret = pread(src, buf, ZF_SPACE, 0);
  PRINT_INFO("Tesla testing %ld", buf->raw_data_size);
  if (ret < (ssize_t)ZF_SPACE) {
    PRINT_ERROR("failed to read file header (fildes: %d).", src);
    return false;
  }
  struct zfile_ht* pht = (struct zfile_ht *)buf;

  struct stat stat;
  fstat(src, &stat);
 
  file_size = stat.st_size;

  PRINT_INFO("get_file_size  %d" , file_size);
  if (trailer) {
    size_t trailer_offset = file_size - ZF_SPACE;
    PRINT_INFO("trailer_offset  %d  " , trailer_offset );
    ret = pread(src, buf, ZF_SPACE , trailer_offset);
    PRINT_INFO("ret %d  " , ret);
    if (ret < (ssize_t)ZF_SPACE) {
      PRINT_ERROR("failed to read file trailer "
                  "(fildes: %ld).",
                  (int)(int)src);
      return false;
    }

    PRINT_INFO("size %d", (uint64_t)buf->index_size);
    PRINT_INFO("offset %d", (uint64_t)buf->index_offset);

    jt_size = ((uint64_t)buf->index_size) * sizeof(uint32_t);
    PRINT_INFO("tailer offset: %ld, idx_offset: %ld, jt_size: %ld, dict_size : %ld "
               , trailer_offset, pht->index_offset, (uint64_t)jt_size, pht->opt.dict_size);

    if (jt_size > trailer_offset - pht->index_offset) {
      PRINT_ERROR("invalid index bytes or size "
                  "(fildes: %d).",
                  (int)(int)src);
      return false;
    }
  }
   
  uint32_t ibuf[((uint64_t) buf->index_size)];
  PRINT_INFO("index_size: %d, index_offset: %d, dict_size: %d", pht->index_size, pht->index_offset, pht->opt.dict_size );
  ret = pread(src, &ibuf, jt_size, pht->index_offset);

  if (ret < (ssize_t) jt_size) {
//_zfile_free(ibuf);
    PRINT_ERROR("failed to read index (fildes: %d).", src);
    return false;
  }
  do_build_jump_table(src, ibuf, pht , dst);
  return true;

}


struct zfile_file *open_ro(int src, int dst, bool verify, bool ownership) {
  struct zfile_file *rst = NULL;
  struct zfile_ht ht;
  struct jump_table jt;
  ssize_t n = 0;
  size_t rst_size = 0;
  if (src == 0) {
    PRINT_ERROR("invalid file ptr. (fildes: %d)", src);
    goto error_ret;
  }

  bool ok = do_load_jump_table(src, dst,  &ht, &jt, true);

  if (!ok) {
#ifndef __KERNEL__
    errno = EIO;
#endif
    PRINT_ERROR("failed to load index from file (fildes: %d).",
                (int)(int)src);
    goto error_ret;
  }
  return rst;

error_ret:
  return NULL;
}

int main(int argc, char **argv)
{
    char buffer[ZF_SPACE];
    int files[2];
    ssize_t count;

    /* Check for insufficient parameters */
    if (argc < 3)
        return -1;
    files[0] = open(argv[1], O_RDONLY);
    if (files[0] == -1) {
	PRINT_INFO("can't open source file %s", argv[1]);
	return -1;
     } 
    

    files[1] = open(argv[2], O_CREAT | S_IRUSR | S_IWUSR);
    if (files[1] == -1) /* Check if file opened (permissions problems ...) */
    {
	PRINT_INFO("can't open dst file %s", argv[2]);
        close(files[0]);
        return -1;
    }
    
    PRINT_INFO("Trying to access the fault fault %ld" , files[0]); 
    char data[ZF_SPACE];
    size_t readn = pread(files[0], data, ZF_SPACE, 0);
    if (readn < ZF_SPACE) {
       PRINT_INFO("invalid file ptr. (fildes: %d)", files[0]);
    }
    open_ro(files[0], files[1], false, false);
    //while ((count = read(files[0], buffer, sizeof(buffer))) != 0)
    //    write(files[1], buffer, count);
    close(files[0]);
    close(files[1]);

    return 0;
}


