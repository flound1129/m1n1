/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "heapblock.h"
#include "assert.h"
#include "types.h"
#include "utils.h"
#include "xnuboot.h"

/*
 * This is a non-freeing allocator, used as a backend for malloc and for uncompressing data.
 *
 * Allocating 0 bytes is allowed, and guarantees "infinite" (until the end of RAM) space is
 * available at the returned pointer as long as no other malloc/heapblock calls occur, which is
 * useful as a buffer for unknown-length uncompressed data. A subsequent call with a size will then
 * actually reserve the block.
 */

static void *heap_base;
static void *heap_limit;
static void *heap_top;

void heapblock_init(void)
{
    void *top_of_kernel_data = (void *)cur_boot_args.top_of_kernel_data;

    heap_base = top_of_kernel_data;
    heapblock_alloc(0); // align base

    printf("Heap base: %p\n", heap_base);
}

void heapblock_set_limit(void *limit)
{
    heap_limit = limit;
    if (heap_base && limit && (uintptr_t)limit >= (uintptr_t)heap_base)
        printf("Heap limit: %p (%lu MiB)\n", limit,
               ((uintptr_t)limit - (uintptr_t)heap_base) >> 20);
    else
        printf("Heap limit: %p\n", limit);
}

void *heapblock_get_cursor(void)
{
    return heap_base;
}

void *heapblock_get_limit(void)
{
    if (heap_top && (!heap_limit || (uintptr_t)heap_top < (uintptr_t)heap_limit))
        return heap_top;
    return heap_limit;
}

void heapblock_reserve_top(void *limit)
{
    if (!limit || (heap_base && (uintptr_t)limit < (uintptr_t)heap_base) ||
        (heap_top && (uintptr_t)limit > (uintptr_t)heap_top))
        panic("heapblock: invalid top reservation (cursor %p, top %p, new top %p)\n",
              heap_base, heap_top, limit);

    /* A requested/proxy heap limit cannot release live top reservations. */
    heap_top = limit;
}

void *heapblock_alloc(size_t size)
{
    return heapblock_alloc_aligned(size, 64);
}

void *heapblock_alloc_aligned(size_t size, size_t align)
{
    assert(align && (align & (align - 1)) == 0);
    assert(heap_base);

    uintptr_t aligned, end;
    if (__builtin_add_overflow((uintptr_t)heap_base, align - 1, &aligned))
        panic("heapblock: alignment overflow (%zu at %p)\n", align, heap_base);
    uintptr_t block = aligned & ~(align - 1);
    if (__builtin_add_overflow(block, size, &end))
        panic("heapblock: allocation overflow (%zu bytes at 0x%lx)\n", size, block);

    void *limit = heapblock_get_limit();
    if (limit && end > (uintptr_t)limit)
        panic("heapblock: out of memory (%zu bytes at 0x%lx, limit %p)\n", size, block, limit);

    heap_base = (void *)end;

    return (void *)block;
}
