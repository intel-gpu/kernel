// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include "gt/intel_gt_requests.h"
#include "intel_memory_region.h"
#include "i915_drv.h"

const struct intel_memory_region_info intel_region_map[] = {
       [INTEL_REGION_SMEM] = {
               .class = INTEL_MEMORY_SYSTEM,
               .instance = 0,
       },
       [INTEL_REGION_LMEM] = {
               .class = INTEL_MEMORY_LOCAL,
               .instance = 0,
       },
       [INTEL_REGION_STOLEN_SMEM] = {
               .class = INTEL_MEMORY_STOLEN_SYSTEM,
               .instance = 0,
       },
       [INTEL_REGION_STOLEN_LMEM] = {
               .class = INTEL_MEMORY_STOLEN_LOCAL,
               .instance = 0,
       },
};

struct intel_memory_region *
intel_memory_region_lookup(struct drm_i915_private *i915,
			   u16 class, u16 instance)
{
	int i;

	/* XXX: consider maybe converting to an rb tree at some point */
	for (i = 0; i < ARRAY_SIZE(i915->mm.regions); ++i) {
		struct intel_memory_region *region = i915->mm.regions[i];

		if (!region)
			continue;

		if (region->type == class && region->instance == instance)
			return region;
	}

	return NULL;
}

struct intel_memory_region *
intel_memory_region_by_type(struct drm_i915_private *i915,
			    enum intel_memory_type mem_type)
{
	struct intel_memory_region *mr;
	int id;

	for_each_memory_region(mr, i915, id)
		if (mr->type == mem_type)
			return mr;

	return NULL;
}

static u64
intel_memory_region_free_pages(struct intel_memory_region *mem,
			       struct list_head *blocks)
{
	struct i915_buddy_block *block, *on;
	u64 size = 0;

	list_for_each_entry_safe(block, on, blocks, link) {
		size += i915_buddy_block_size(&mem->mm, block);
		i915_buddy_free(&mem->mm, block);
	}
	INIT_LIST_HEAD(blocks);

	return size;
}

void
__intel_memory_region_put_pages_buddy(struct intel_memory_region *mem,
				      struct list_head *blocks)
{
	mutex_lock(&mem->mm_lock);
	mem->avail += intel_memory_region_free_pages(mem, blocks);
	mutex_unlock(&mem->mm_lock);
}

static void __intel_memory_region_put_block_work(struct work_struct *work)
{
	struct intel_memory_region *mem =
		container_of(work, struct intel_memory_region, pd_put.work);
	struct llist_node *freed = llist_del_all(&mem->pd_put.blocks);
	struct i915_buddy_block *block;
	struct list_head blocks;

	INIT_LIST_HEAD(&blocks);

	llist_for_each_entry(block, freed, freed)
		list_add(&block->link, &blocks);

	__intel_memory_region_put_pages_buddy(mem, &blocks);
}

void
__intel_memory_region_put_block_buddy(struct i915_buddy_block *block)
{
	struct intel_memory_region *mem = block->private;

	if (llist_add(&block->freed, &mem->pd_put.blocks))
		schedule_work(&mem->pd_put.work);
}

static int intel_memory_region_evict(struct intel_memory_region *mem,
				     resource_size_t target)
{
	struct drm_i915_private *i915 = mem->i915;
	struct list_head still_in_list;
	struct drm_i915_gem_object *obj;
	struct list_head *phases[] = {
		&mem->objects.purgeable,
		&mem->objects.list,
		NULL,
	};
	struct list_head **phase;
	resource_size_t found;
	int pass;

	intel_gt_retire_requests(&i915->gt);

	found = 0;
	pass = 0;
	phase = phases;

next:
	INIT_LIST_HEAD(&still_in_list);
	mutex_lock(&mem->objects.lock);

	while (found < target &&
		(obj = list_first_entry_or_null(*phase,
						typeof(*obj),
						mm.region_link))) {
		list_move_tail(&obj->mm.region_link, &still_in_list);

		if (!i915_gem_object_has_pages(obj))
			continue;
		if (i915_gem_object_is_framebuffer(obj))
			continue;
		if (atomic_read(&obj->mm.pages_pin_count) >
		    atomic_read(&obj->bind_count))
			continue;

		/*
		 * For IOMEM region, only swap user space objects.
		 * kernel objects are bound and causes a lot of unbind
		 * warning message in driver.
		 * FIXME: swap kernel object as well.
		 */
		if (i915_gem_object_type_has(obj, I915_GEM_OBJECT_HAS_IOMEM)
		    && !obj->base.handle_count)
			continue;

		if (!kref_get_unless_zero(&obj->base.refcount))
			continue;

		mutex_unlock(&mem->objects.lock);

		/* tell callee to do swapping */
		if (i915_gem_object_type_has(obj, I915_GEM_OBJECT_HAS_IOMEM)
		    && pass == 1)
			obj->do_swapping = true;

		/*
		 * FIXME: We need  to unbind the active vmas too. But with the
		 * async vma_bind through dma_fence work, along with active vma
		 * eviction is causing the mutex deadlock at multi instance gaming
		 * scenario. Hoping that this will be fixed with dma_resv based
		 * eviction.
		 */
		if (!i915_gem_object_unbind(obj, 0)) {
			__i915_gem_object_put_pages(obj);
			/* May arrive from get_pages on another bo */
			mutex_lock(&obj->mm.lock);
			if (!i915_gem_object_has_pages(obj)) {
				found += obj->base.size;
				if (obj->mm.madv == I915_MADV_DONTNEED)
					obj->mm.madv = __I915_MADV_PURGED;
			}
			mutex_unlock(&obj->mm.lock);
		}

		obj->do_swapping = false;
		i915_gem_object_put(obj);
		mutex_lock(&mem->objects.lock);

		if (found >= target)
			break;
	}
	list_splice_tail(&still_in_list, *phase);
	mutex_unlock(&mem->objects.lock);

	if (found < target && i915->params.enable_eviction) {
		pass++;
		phase++;
		if (*phase)
			goto next;
	}

	return (found < target) ? -ENOSPC : 0;
}

int
__intel_memory_region_get_pages_buddy(struct intel_memory_region *mem,
				      resource_size_t size,
				      unsigned int flags,
				      struct list_head *blocks)
{
	unsigned int min_order = 0;
	unsigned int max_order;
	unsigned long n_pages;

	GEM_BUG_ON(!IS_ALIGNED(size, mem->mm.chunk_size));
	GEM_BUG_ON(!list_empty(blocks));

	if (flags & I915_ALLOC_MIN_PAGE_SIZE) {
		min_order = ilog2(mem->min_page_size) -
			    ilog2(mem->mm.chunk_size);
	}

	if (flags & I915_ALLOC_CONTIGUOUS) {
		size = roundup_pow_of_two(size);
		min_order = ilog2(size) - ilog2(mem->mm.chunk_size);
	}

	if (size > mem->mm.size)
		return -E2BIG;

	n_pages = size >> ilog2(mem->mm.chunk_size);

	/*
	 * When allocating pages for an lmem object of size > 4G
	 * the memory blocks allocated from buddy system could be
	 * from sizes greater than 4G requiring > 32b to represent
	 * block size. But those blocks cannot be used in sg list
	 * construction(in caller) as sg->length is only 32b wide.
	 * Hence limiting the block size to 4G.
	 */
	max_order = (ilog2(SZ_4G) - 1) - ilog2(mem->mm.chunk_size);

	mutex_lock(&mem->mm_lock);

	do {
		struct i915_buddy_block *block;
		unsigned int order;
retry:
		order = min_t(u32, (fls(n_pages) - 1), max_order);
		GEM_BUG_ON(order > mem->mm.max_order);
		GEM_BUG_ON(order < min_order);

		do {
			block = i915_buddy_alloc(&mem->mm, order);
			if (!IS_ERR(block))
				break;

			if (order-- == min_order) {
				resource_size_t target;
				int err;

				target = n_pages * mem->mm.chunk_size;

				mutex_unlock(&mem->mm_lock);
				err = intel_memory_region_evict(mem,
								target);
				mutex_lock(&mem->mm_lock);
				if (err)
					goto err_free_blocks;

				goto retry;
			}
		} while (1);

		n_pages -= BIT(order);

		block->private = mem;
		list_add(&block->link, blocks);

		if (!n_pages)
			break;
	} while (1);

	mem->avail -= size;
	mutex_unlock(&mem->mm_lock);
	return 0;

err_free_blocks:
	intel_memory_region_free_pages(mem, blocks);
	mutex_unlock(&mem->mm_lock);
	return -ENXIO;
}

struct i915_buddy_block *
__intel_memory_region_get_block_buddy(struct intel_memory_region *mem,
				      resource_size_t size,
				      unsigned int flags)
{
	struct i915_buddy_block *block;
	LIST_HEAD(blocks);
	int ret;

	ret = __intel_memory_region_get_pages_buddy(mem, size, flags, &blocks);
	if (ret)
		return ERR_PTR(ret);

	block = list_first_entry(&blocks, typeof(*block), link);
	list_del_init(&block->link);
	return block;
}

int intel_memory_region_init_buddy(struct intel_memory_region *mem)
{
	return i915_buddy_init(&mem->mm, resource_size(&mem->region),
			       PAGE_SIZE);
}

void intel_memory_region_release_buddy(struct intel_memory_region *mem)
{
	i915_buddy_free_list(&mem->mm, &mem->reserved);
	i915_buddy_fini(&mem->mm);
}

struct intel_memory_region *
intel_memory_region_create(struct drm_i915_private *i915,
			   resource_size_t start,
			   resource_size_t size,
			   resource_size_t min_page_size,
			   resource_size_t io_start,
			   const struct intel_memory_region_ops *ops)
{
	struct intel_memory_region *mem;
	int err;

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return ERR_PTR(-ENOMEM);

	mem->i915 = i915;
	mem->region = (struct resource)DEFINE_RES_MEM(start, size);
	mem->io_start = io_start;
	mem->min_page_size = min_page_size;
	mem->ops = ops;
	mem->total = size;
	mem->avail = mem->total;

	INIT_WORK(&mem->pd_put.work, __intel_memory_region_put_block_work);

	mutex_init(&mem->objects.lock);
	INIT_LIST_HEAD(&mem->objects.list);
	INIT_LIST_HEAD(&mem->objects.purgeable);
	INIT_LIST_HEAD(&mem->reserved);

	mutex_init(&mem->mm_lock);

	if (ops->init) {
		err = ops->init(mem);
		if (err)
			goto err_free;
	}

	kref_init(&mem->kref);
	return mem;

err_free:
	kfree(mem);
	return ERR_PTR(err);
}

void intel_memory_region_set_name(struct intel_memory_region *mem,
				  const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(mem->name, sizeof(mem->name), fmt, ap);
	va_end(ap);
}

static void __intel_memory_region_destroy(struct kref *kref)
{
	struct intel_memory_region *mem =
		container_of(kref, typeof(*mem), kref);

	/* Flush any pending work to free blocks region */
	flush_work(&mem->pd_put.work);

	if (mem->ops->release)
		mem->ops->release(mem);

	mutex_destroy(&mem->mm_lock);
	mutex_destroy(&mem->objects.lock);
	kfree(mem);
}

struct intel_memory_region *
intel_memory_region_get(struct intel_memory_region *mem)
{
	kref_get(&mem->kref);
	return mem;
}

void intel_memory_region_put(struct intel_memory_region *mem)
{
	kref_put(&mem->kref, __intel_memory_region_destroy);
}

/* Global memory region registration -- only slight layer inversions! */

int intel_memory_regions_hw_probe(struct drm_i915_private *i915)
{
	int err, i;

	/* All platforms currently have system memory */
	GEM_BUG_ON(!HAS_REGION(i915, REGION_SMEM));

	if (IS_DGFX(i915)) {
		if (IS_ENABLED(CONFIG_DRM_I915_PCIE_STRICT_WRITE_ORDERING))
			pcie_capability_clear_word(i915->drm.pdev, PCI_EXP_DEVCTL,
						   PCI_EXP_DEVCTL_RELAX_EN);
		else
			pcie_capability_set_word(i915->drm.pdev, PCI_EXP_DEVCTL,
						 PCI_EXP_DEVCTL_RELAX_EN);
	}

	for (i = 0; i < ARRAY_SIZE(i915->mm.regions); i++) {
		struct intel_memory_region *mem = ERR_PTR(-ENODEV);
		u16 type, instance;

		if (!HAS_REGION(i915, BIT(i)))
			continue;

		type = intel_region_map[i].class;
		instance = intel_region_map[i].instance;
		switch (type) {
		case INTEL_MEMORY_SYSTEM:
			mem = i915_gem_shmem_setup(i915);
			break;
		case INTEL_MEMORY_STOLEN_LOCAL: /* fallthrough */
		case INTEL_MEMORY_STOLEN_SYSTEM:
			mem = i915_gem_stolen_setup(i915);
			break;
		case INTEL_MEMORY_LOCAL:
#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
			if (IS_ENABLED(CONFIG_DRM_I915_UNSTABLE_FAKE_LMEM)) {
				if (INTEL_GEN(i915) >= 9 && i915_selftest.live < 0 &&
				    i915->params.fake_lmem_start)
					mem = intel_setup_fake_lmem(i915);
			}
#endif

			if (IS_ERR(mem))
				mem = i915_gem_setup_lmem(i915);
			break;
		}

		if (IS_ERR(mem)) {
			err = PTR_ERR(mem);
			drm_err(&i915->drm,
				"Failed to setup region(%d) type=%d\n",
				err, type);
			goto out_cleanup;
		}

		mem->id = i;
		mem->type = type;
		mem->instance = instance;
		mem->gt = &i915->gt;

		if (HAS_LMEM(mem->i915) && type != INTEL_MEMORY_SYSTEM)
			intel_memory_region_set_name(mem, "%s%u",
						     mem->name, mem->instance);

		i915->mm.regions[i] = mem;
	}

	return 0;

out_cleanup:
	intel_memory_regions_driver_release(i915);
	return err;
}

void intel_memory_regions_driver_release(struct drm_i915_private *i915)
{
	int i;

	/* flush pending work that might use the memory regions */
	flush_workqueue(i915->wq);

	for (i = 0; i < ARRAY_SIZE(i915->mm.regions); i++) {
		struct intel_memory_region *region =
			fetch_and_zero(&i915->mm.regions[i]);

		if (region)
			intel_memory_region_put(region);
	}
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/intel_memory_region.c"
#include "selftests/mock_region.c"
#endif
