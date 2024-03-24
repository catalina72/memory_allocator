// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "block_meta.h"

#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

struct block_meta *global_base;

int heap_preallocation;

struct block_meta *request_space(struct block_meta *last, size_t size);
void split_block(struct block_meta *block, size_t size);
void coalesce(struct block_meta *block);
struct block_meta *find_best_block(struct block_meta **last, size_t size);
struct block_meta *expand_block(struct block_meta *block, size_t new_size);

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	struct block_meta *block;
	size_t aligned = ALIGN(size);

	if (size <= 0)
		return NULL;
	if (!global_base) {
		block = request_space(NULL, aligned + META_SIZE);
		if (!block)
			return NULL;
		global_base = block;
		block->next = NULL;
		block->prev = NULL;
	} else {
		struct block_meta *last = global_base;

		block = find_best_block(&last, aligned + META_SIZE);
		if (!block) {
			block = request_space(last, aligned + META_SIZE);
			if (!block)
				return NULL;
		} else {
			split_block(block, aligned + META_SIZE);
		}
	}
	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;
	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce(block);
	}
	if (block->status == STATUS_MAPPED) {
		block->status = STATUS_FREE;
		DIE(munmap(block, block->size + META_SIZE) == -1, "munmap failed");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	struct block_meta *block;

	if (nmemb == 0 || size == 0)
		return NULL;
	size_t aligned = ALIGN(nmemb * size);
	struct block_meta *last = global_base;

	while (last && last->next)
		last = last->next;
	if (aligned + META_SIZE > (size_t)(getpagesize())) {
		block = mmap(NULL, aligned + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		block->size = aligned;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_MAPPED;
		memset((void *)(block + 1), 0, aligned);
		return (void *)(block + 1);
	}
	void *ptr = os_malloc(nmemb * size);

	memset(ptr, 0, size * nmemb);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (!ptr)
		return os_malloc(size);
	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_FREE)
		return NULL;
	size_t aligned = ALIGN(size);

	if (block->status == STATUS_MAPPED || heap_preallocation == 0 || aligned >= MMAP_THRESHOLD) {
		void *new_ptr = os_malloc(size);

		memcpy(new_ptr, ptr, aligned < block->size ? aligned:block->size);
		os_free(ptr);
		return new_ptr;
	}
	if (aligned <= block->size) {
		split_block(block, aligned + META_SIZE);
		return ptr;
	}
	struct block_meta *last = global_base;

	while (last && last->next != NULL)
		last = last->next;
	if (block == last) {
		expand_block(block, aligned + META_SIZE);
		return ptr;
	}
	struct block_meta *next_block = block->next;

	while (next_block != NULL && next_block->status == STATUS_FREE) {
		size_t total_size = block->size + next_block->size + META_SIZE;

		if (total_size >= aligned) {
			block->size = total_size;
			block->next = next_block->next;
			block->status = STATUS_ALLOC;
			if (block->next)
				block->next->prev = block;
			if (total_size - (aligned - META_SIZE) > META_SIZE)
				split_block(block, aligned + META_SIZE);
			return ptr;
		}
		next_block = next_block->next;
	}
	void *new_ptr = os_malloc(size);

	if (new_ptr == NULL)
		return NULL;
	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}

struct block_meta *request_space(struct block_meta *last, size_t size)
{
	struct block_meta *block;

	if (size < MMAP_THRESHOLD) {
		block = sbrk(0);
		DIE(block == NULL, "sbrk failed");
		if (heap_preallocation == 0) {
			heap_preallocation = 1;
			block = sbrk(MMAP_THRESHOLD);
			DIE(block == NULL, "sbrk failed");
			block->next = NULL;
			block->prev = NULL;
			block->size = MMAP_THRESHOLD - META_SIZE;
			block->status = STATUS_ALLOC;
		} else {
			if (last && last->status == STATUS_FREE) {
				block = expand_block(last, size);
			} else {
				block = sbrk(size);
				DIE(block == NULL, "sbrk failed");
				if (last) {
					last->next = block;
					block->prev = last;
				} else {
					block->prev = NULL;
				}
			}
			block->size = size - META_SIZE;
			block->next = NULL;
			block->status = STATUS_ALLOC;
		}
	} else {
		block = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		block->size = size - META_SIZE;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_MAPPED;
	}
	return block;
}

void split_block(struct block_meta *block, size_t size)
{
	size_t remaining_size = block->size - size + META_SIZE;

	if (remaining_size > META_SIZE) {
		struct block_meta *remaining_block = (struct block_meta *)((char *)block + size);

		remaining_block->size = remaining_size - META_SIZE;
		remaining_block->next = block->next;
		remaining_block->prev = block;
		remaining_block->status = STATUS_FREE;
		if (block->next)
			block->next->prev = remaining_block;
		block->next = remaining_block;
		block->size = size - META_SIZE;
	}
	block->status = STATUS_ALLOC;
}

void coalesce(struct block_meta *block)
{
	if (block->next && block->next->status == STATUS_FREE) {
		block->size += block->next->size + META_SIZE;
		block->next = block->next->next;
		if (block->next)
			block->next->prev = block;
	}

	if (block->prev && block->prev->status == STATUS_FREE) {
		block->prev->size += block->size + META_SIZE;
		block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;
		block = block->prev;
	}
}

struct block_meta *find_best_block(struct block_meta **last, size_t size)
{
	struct block_meta *best = NULL;

	for (struct block_meta *aux = global_base; aux != NULL; aux = aux->next) {
		*last = aux;
		if (aux->status == STATUS_FREE)
			if (aux->size >= size - META_SIZE && (best == NULL || aux->size < best->size))
				best = aux;
	}
	return best;
}

struct block_meta *expand_block(struct block_meta *block, size_t new_size)
{
	if (block == NULL)
		return NULL;
	size_t current_size = block->size;

	if (new_size < current_size)
		return block;
	void *new_block = sbrk(new_size - current_size - META_SIZE);

	DIE(new_block == NULL, "sbrk failed");
	block->size = new_size - META_SIZE;
	block->status = STATUS_ALLOC;
	return block;
}
