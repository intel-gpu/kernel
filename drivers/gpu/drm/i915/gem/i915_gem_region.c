// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include "intel_memory_region.h"
#include "i915_gem_region.h"
#include "i915_drv.h"
#include "i915_trace.h"
#include "i915_gem_mman.h"

static int
i915_gem_object_swapout_pages(struct drm_i915_gem_object *obj,
			      struct sg_table *pages, unsigned int sizes)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct drm_i915_gem_object *dst, *src;
	unsigned long start, diff, msec;
	bool blt_completed = false;
	int err = -EINVAL;

	GEM_BUG_ON(obj->swapto);
	GEM_BUG_ON(i915_gem_object_has_pages(obj));
	GEM_BUG_ON(obj->mm.madv != I915_MADV_WILLNEED);
	GEM_BUG_ON(obj->mm.region->type != INTEL_MEMORY_LOCAL);
	GEM_BUG_ON(!i915->params.enable_eviction);

	lockdep_assert_held(&obj->mm.lock);
	start = jiffies;

	/* create an shadow object on smem region */
	dst = i915_gem_object_create_shmem(i915, obj->base.size);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	/*
	 * create working object on the same region as 'obj',
	 * if 'obj' is used directly, it is set pages and is pinned
	 * again, other thread may wrongly use 'obj' pages.
	 */
	src = i915_gem_object_create_region(obj->mm.region,
					    obj->base.size, 0);
	if (IS_ERR(src)) {
		i915_gem_object_put(dst);
		return PTR_ERR(src);
	}

	/* set and pin working object pages */
	mutex_lock_nested(&src->mm.lock, I915_MM_EVICTION);
	__i915_gem_object_set_pages(src, pages, sizes);
	__i915_gem_object_pin_pages(src);
	mutex_unlock(&src->mm.lock);

	/* revoke pages mapped into userspace */
	i915_gem_object_release_mmap(obj);

	/* copying the pages */
	if (i915->params.enable_eviction >= 2) {
		err = i915_window_blt_copy(dst, src);
		if (!err)
			blt_completed = true;
	}
	if (err && i915->params.enable_eviction != 2)
		err = i915_gem_object_memcpy(dst, src);

	__i915_gem_object_unpin_pages(src);
	__i915_gem_object_unset_pages(src);
	i915_gem_object_put(src);

	if (!err)
		obj->swapto = dst;
	else
		i915_gem_object_put(dst);

	if (!err) {
		diff = jiffies - start;
		msec = diff * 1000 / HZ;
		if (blt_completed) {
			atomic_long_add(sizes, &i915->num_bytes_swapped_out);
			atomic_long_add(msec, &i915->time_swap_out_ms);
		} else {
			atomic_long_add(sizes,
					&i915->num_bytes_swapped_out_memcpy);
			atomic_long_add(msec, &i915->time_swap_out_ms_memcpy);
		}
	}

	return err;
}

static int
i915_gem_object_swapin_pages(struct drm_i915_gem_object *obj,
			     struct sg_table *pages, unsigned int sizes)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct drm_i915_gem_object *dst, *src;
	unsigned long start, diff, msec;
	bool blt_completed = false;
	int err = -EINVAL;

	GEM_BUG_ON(!obj->swapto);
	GEM_BUG_ON(i915_gem_object_has_pages(obj));
	GEM_BUG_ON(obj->mm.madv != I915_MADV_WILLNEED);
	GEM_BUG_ON(obj->mm.region->type != INTEL_MEMORY_LOCAL);
	GEM_BUG_ON(!i915->params.enable_eviction);

	lockdep_assert_held(&obj->mm.lock);
	start = jiffies;

	src = obj->swapto;

	/*
	 * create working object on the same region as 'obj',
	 * if 'obj' is used directly, it is set pages and is pinned
	 * again, other thread may wrongly use 'obj' pages.
	 */
	dst = i915_gem_object_create_region(obj->mm.region,
					    obj->base.size, 0);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		return err;
	}

	/* set and pin working object pages */
	mutex_lock_nested(&dst->mm.lock, I915_MM_EVICTION);
	__i915_gem_object_set_pages(dst, pages, sizes);
	__i915_gem_object_pin_pages(dst);
	mutex_unlock(&dst->mm.lock);

	/* copying the pages */
	if (i915->params.enable_eviction >= 2) {
		err = i915_window_blt_copy(dst, src);
		if (!err)
			blt_completed = true;
	}
	if (err && i915->params.enable_eviction != 2)
		err = i915_gem_object_memcpy(dst, src);

	__i915_gem_object_unpin_pages(dst);
	__i915_gem_object_unset_pages(dst);
	i915_gem_object_put(dst);

	if (!err) {
		obj->swapto = NULL;
		i915_gem_object_put(src);
	}

	if (!err) {
		diff = jiffies - start;
		msec = diff * 1000 / HZ;
		if (blt_completed) {
			atomic_long_add(sizes, &i915->num_bytes_swapped_in);
			atomic_long_add(msec, &i915->time_swap_in_ms);
		} else {
			atomic_long_add(sizes,
					&i915->num_bytes_swapped_in_memcpy);
			atomic_long_add(msec, &i915->time_swap_in_ms_memcpy);
		}
	}

	return err;
}

void
i915_gem_object_put_pages_buddy(struct drm_i915_gem_object *obj,
				struct sg_table *pages)
{
	/* if need to save the page contents, swap them out */
	if (obj->do_swapping) {
		unsigned int sizes = obj->mm.page_sizes.phys;

		GEM_BUG_ON(obj->mm.madv != I915_MADV_WILLNEED);
		GEM_BUG_ON(i915_gem_object_is_volatile(obj));

		if (i915_gem_object_swapout_pages(obj, pages, sizes)) {
			/* swapout failed, keep the pages */
			__i915_gem_object_set_pages(obj, pages, sizes);
			return;
		}
	}

	__intel_memory_region_put_pages_buddy(obj->mm.region, &obj->mm.blocks);

	obj->mm.dirty = false;
	sg_free_table(pages);
	kfree(pages);
}

int
i915_gem_object_get_pages_buddy(struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct intel_memory_region *mem = obj->mm.region;
	struct list_head *blocks = &obj->mm.blocks;
	resource_size_t size = obj->base.size;
	resource_size_t prev_end;
	struct i915_buddy_block *block;
	unsigned int flags;
	struct sg_table *st;
	struct scatterlist *sg;
	unsigned int sg_page_sizes;
	int ret;

	/* XXX: Check if we have any post. This is nasty hack, see gem_create */
	if (obj->mm.gem_create_posted_err)
		return obj->mm.gem_create_posted_err;

	st = kmalloc(sizeof(*st), GFP_KERNEL);
	if (!st)
		return -ENOMEM;

	if (sg_alloc_table(st, size >> ilog2(mem->mm.chunk_size), GFP_KERNEL)) {
		kfree(st);
		return -ENOMEM;
	}

	flags = I915_ALLOC_MIN_PAGE_SIZE;
	if (obj->flags & I915_BO_ALLOC_CONTIGUOUS)
		flags |= I915_ALLOC_CONTIGUOUS;

	ret = __intel_memory_region_get_pages_buddy(mem, size, flags, blocks);
	if (ret)
		goto err_free_sg;

	GEM_BUG_ON(list_empty(blocks));

	sg = st->sgl;
	st->nents = 0;
	sg_page_sizes = 0;
	prev_end = (resource_size_t)-1;

	list_for_each_entry(block, blocks, link) {
		u64 block_size, offset;

		block_size = min_t(u64, size,
				   i915_buddy_block_size(&mem->mm, block));
		offset = i915_buddy_block_offset(block);

		GEM_BUG_ON(overflows_type(block_size, sg->length));

		if (offset != prev_end ||
		    add_overflows_t(typeof(sg->length), sg->length, block_size)) {
			if (st->nents) {
				sg_page_sizes |= sg->length;
				sg = __sg_next(sg);
			}

			sg_dma_address(sg) = mem->region.start + offset;
			sg_dma_len(sg) = block_size;

			sg->length = block_size;

			st->nents++;
		} else {
			sg->length += block_size;
			sg_dma_len(sg) += block_size;
		}

		prev_end = offset + block_size;
	}

	sg_page_sizes |= sg->length;
	sg_mark_end(sg);
	i915_sg_trim(st);

	/* if we saved the page contents, swap them in */
	if (obj->swapto) {
		GEM_BUG_ON(i915_gem_object_is_volatile(obj));
		GEM_BUG_ON(!i915->params.enable_eviction);

		ret = i915_gem_object_swapin_pages(obj, st,
						   sg_page_sizes);
		if (ret) {
			/* swapin failed, free the pages */
			__intel_memory_region_put_pages_buddy(mem, blocks);
			ret = -ENXIO;
			goto err_free_sg;
		}
	} else if (obj->flags & I915_BO_ALLOC_CPU_CLEAR) {
		struct scatterlist *sg;
		unsigned long i;

		for_each_sg(st->sgl, sg, st->nents, i) {
			unsigned int length;
			void __iomem *vaddr;
			dma_addr_t daddr;

			daddr = sg_dma_address(sg);
			daddr -= mem->region.start;
			length = sg_dma_len(sg);

			vaddr = io_mapping_map_wc(&mem->iomap, daddr, length);
			memset64(vaddr, 0, length / sizeof(u64));
			io_mapping_unmap(vaddr);
		}
	}

	__i915_gem_object_set_pages(obj, st, sg_page_sizes);

	return 0;

err_free_sg:
	sg_free_table(st);
	kfree(st);
	return ret;
}

void i915_gem_object_init_memory_region(struct drm_i915_gem_object *obj,
					struct intel_memory_region *mem,
					unsigned long flags)
{
	INIT_LIST_HEAD(&obj->mm.blocks);
	obj->mm.region = intel_memory_region_get(mem);

	obj->flags |= flags;
	if (obj->base.size <= mem->min_page_size)
		obj->flags |= I915_BO_ALLOC_CONTIGUOUS;

	mutex_lock(&mem->objects.lock);

	if (obj->flags & I915_BO_ALLOC_VOLATILE)
		list_add_tail(&obj->mm.region_link, &mem->objects.purgeable);
	else
		list_add_tail(&obj->mm.region_link, &mem->objects.list);

	mutex_unlock(&mem->objects.lock);
}

void i915_gem_object_release_memory_region(struct drm_i915_gem_object *obj)
{
	struct intel_memory_region *mem = obj->mm.region;

	mutex_lock(&mem->objects.lock);
	list_del(&obj->mm.region_link);
	mutex_unlock(&mem->objects.lock);

	intel_memory_region_put(mem);
}

struct drm_i915_gem_object *
i915_gem_object_create_region(struct intel_memory_region *mem,
			      resource_size_t size,
			      unsigned int flags)
{
	struct drm_i915_gem_object *obj;

	/*
	 * NB: Our use of resource_size_t for the size stems from using struct
	 * resource for the mem->region. We might need to revisit this in the
	 * future.
	 */

	GEM_BUG_ON(flags & ~I915_BO_ALLOC_FLAGS);

	if (!mem)
		return ERR_PTR(-ENODEV);

	size = round_up(size, mem->min_page_size);

	GEM_BUG_ON(!size);
	GEM_BUG_ON(!IS_ALIGNED(size, I915_GTT_MIN_ALIGNMENT));

	/*
	 * XXX: There is a prevalence of the assumption that we fit the
	 * object's page count inside a 32bit _signed_ variable. Let's document
	 * this and catch if we ever need to fix it. In the meantime, if you do
	 * spot such a local variable, please consider fixing!
	 */

	if (size >> PAGE_SHIFT > INT_MAX)
		return ERR_PTR(-E2BIG);

	if (overflows_type(size, obj->base.size))
		return ERR_PTR(-E2BIG);

	obj = mem->ops->create_object(mem, size, flags);
	if (!IS_ERR(obj))
		trace_i915_gem_object_create(obj);

	return obj;
}
