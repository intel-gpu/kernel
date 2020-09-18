/*
 * Copyright © 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include <linux/sched/mm.h>

#include "display/intel_frontbuffer.h"
#include "gt/intel_gt.h"
#include "gt/intel_gt_requests.h"
#include "gt/intel_ring.h"
#include "i915_drv.h"
#include "i915_gem_clflush.h"
#include "i915_gem_context.h"
#include "i915_gem_mman.h"
#include "i915_gem_object.h"
#include "i915_gem_object_blt.h"
#include "i915_gem_region.h"
#include "i915_gem_lmem.h"
#include "i915_globals.h"
#include "i915_trace.h"
#include "i915_memcpy.h"

static struct i915_global_object {
	struct i915_global base;
	struct kmem_cache *slab_objects;
} global;

struct drm_i915_gem_object *i915_gem_object_alloc(void)
{
	return kmem_cache_zalloc(global.slab_objects, GFP_KERNEL);
}

void i915_gem_object_free(struct drm_i915_gem_object *obj)
{
	return kmem_cache_free(global.slab_objects, obj);
}

void i915_gem_object_init(struct drm_i915_gem_object *obj,
			  const struct drm_i915_gem_object_ops *ops,
			  struct lock_class_key *key)
{
	__mutex_init(&obj->mm.lock, "obj->mm.lock", key);

	spin_lock_init(&obj->vma.lock);
	INIT_LIST_HEAD(&obj->vma.list);

	INIT_LIST_HEAD(&obj->mm.link);

	INIT_LIST_HEAD(&obj->lut_list);

	INIT_LIST_HEAD(&obj->client_list);

	spin_lock_init(&obj->mmo.lock);
	obj->mmo.offsets = RB_ROOT;

	init_rcu_head(&obj->rcu);

	obj->ops = ops;

	obj->mm.madv = I915_MADV_WILLNEED;
	INIT_RADIX_TREE(&obj->mm.get_page.radix, GFP_KERNEL | __GFP_NOWARN);
	mutex_init(&obj->mm.get_page.lock);
}

static bool i915_gem_object_use_llc(struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	if (HAS_LLC(i915))
		return true;

	if (IS_DGFX(i915) && HAS_SNOOP(i915) &&
	    !i915_gem_object_is_lmem(obj))
		return true;

	return false;
}

/**
 * Mark up the object's coherency levels for a given cache_level
 * @obj: #drm_i915_gem_object
 * @cache_level: cache level
 */
void i915_gem_object_set_cache_coherency(struct drm_i915_gem_object *obj,
					 unsigned int cache_level)
{
	obj->cache_level = cache_level;

	if (cache_level != I915_CACHE_NONE)
		obj->cache_coherent = (I915_BO_CACHE_COHERENT_FOR_READ |
				       I915_BO_CACHE_COHERENT_FOR_WRITE);
	else if (i915_gem_object_use_llc(obj))
		obj->cache_coherent = I915_BO_CACHE_COHERENT_FOR_READ;
	else
		obj->cache_coherent = 0;

	obj->cache_dirty =
		!(obj->cache_coherent & I915_BO_CACHE_COHERENT_FOR_WRITE);
}

int i915_gem_open_object(struct drm_gem_object *gem, struct drm_file *file)
{
	struct drm_i915_gem_object *obj = to_intel_bo(gem);

	return i915_drm_client_add_bo_sz(file, obj);
}

void i915_gem_close_object(struct drm_gem_object *gem, struct drm_file *file)
{
	struct drm_i915_gem_object *obj = to_intel_bo(gem);
	struct drm_i915_file_private *fpriv = file->driver_priv;
	struct i915_mmap_offset *mmo, *mn;
	struct i915_lut_handle *lut, *ln;
	LIST_HEAD(close);

	i915_gem_object_lock(obj);
	list_for_each_entry_safe(lut, ln, &obj->lut_list, obj_link) {
		struct i915_gem_context *ctx = lut->ctx;

		if (ctx->file_priv != fpriv)
			continue;

		i915_gem_context_get(ctx);
		list_move(&lut->obj_link, &close);
	}
	i915_drm_client_del_bo_sz(file, obj);
	i915_gem_object_unlock(obj);

	spin_lock(&obj->mmo.lock);
	rbtree_postorder_for_each_entry_safe(mmo, mn, &obj->mmo.offsets, offset)
		drm_vma_node_revoke(&mmo->vma_node, file);
	spin_unlock(&obj->mmo.lock);

	list_for_each_entry_safe(lut, ln, &close, obj_link) {
		struct i915_gem_context *ctx = lut->ctx;
		struct i915_vma *vma;

		/*
		 * We allow the process to have multiple handles to the same
		 * vma, in the same fd namespace, by virtue of flink/open.
		 */

		mutex_lock(&ctx->mutex);
		vma = radix_tree_delete(&ctx->handles_vma, lut->handle);
		if (vma) {
			GEM_BUG_ON(vma->obj != obj);
			GEM_BUG_ON(!atomic_read(&vma->open_count));
			if (atomic_dec_and_test(&vma->open_count) &&
			    !i915_vma_is_ggtt(vma))
				i915_vma_close(vma);
		}
		mutex_unlock(&ctx->mutex);

		i915_gem_context_put(lut->ctx);
		i915_lut_handle_free(lut);
		i915_gem_object_put(obj);
	}
}

int i915_gem_object_prepare_move(struct drm_i915_gem_object *obj)
{
	int err;

	lockdep_assert_held(&obj->base.dev->struct_mutex);

	if (obj->mm.madv != I915_MADV_WILLNEED)
		return -EINVAL;

	if (i915_gem_object_needs_bit17_swizzle(obj))
		return -EINVAL;

	if (atomic_read(&obj->mm.pages_pin_count) >
	    atomic_read(&obj->bind_count))
		return -EBUSY;

	if (i915_gem_object_is_framebuffer(obj))
		return -EBUSY;

	i915_gem_object_release_mmap(obj);

	GEM_BUG_ON(obj->mm.mapping);
	GEM_BUG_ON(obj->base.filp && mapping_mapped(obj->base.filp->f_mapping));

	err = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE |
				   I915_WAIT_ALL,
				   MAX_SCHEDULE_TIMEOUT);
	if (err)
		return err;

	return i915_gem_object_unbind(obj,
				      I915_GEM_OBJECT_UNBIND_ACTIVE);
}

int i915_gem_object_migrate(struct drm_i915_gem_object *obj,
			    struct intel_context *ce,
			    enum intel_region_id id)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct drm_i915_gem_object *donor;
	struct intel_memory_region *mem;
	struct sg_table *pages = NULL;
	unsigned int page_sizes;
	int err = 0;

	lockdep_assert_held(&i915->drm.struct_mutex);

	GEM_BUG_ON(id >= INTEL_REGION_UNKNOWN);
	GEM_BUG_ON(obj->mm.madv != I915_MADV_WILLNEED);
	if (obj->mm.region->id == id)
		return 0;

	mem = i915->mm.regions[id];

	donor = i915_gem_object_create_region(mem, obj->base.size, 0);
	if (IS_ERR(donor))
		return PTR_ERR(donor);

	/* Copy backing-pages if we have to */
	if (i915_gem_object_has_pages(obj) ||
	    obj->base.filp) {
		err = i915_gem_object_pin_pages(obj);
		if (err)
			goto err_put_donor;

		err = i915_gem_object_copy_blt(obj, donor, ce);
		if (err)
			goto err_put_donor;

		/*
		 * Occasionally i915_gem_object_wait() called inside
		 * i915_gem_object_set_to_cpu_domain() get interrupted
		 * and return -ERESTARTSYS, this will make migration
		 * operation fail. So adding a non-interruptible wait
		 * before changing the object domain.
		 */
		i915_gem_object_lock(donor);
		err = i915_gem_object_wait(donor, 0, MAX_SCHEDULE_TIMEOUT);
		if (!err)
			err = i915_gem_object_set_to_cpu_domain(donor, false);
		i915_gem_object_unlock(donor);
		if (err)
			goto err_put_donor;

		intel_gt_retire_requests(&i915->gt);

		i915_gem_object_unbind(donor, 0);
		err = i915_gem_object_unbind(obj, 0);
		if (err)
			goto err_put_donor;

		mutex_lock(&obj->mm.lock);

		pages = __i915_gem_object_unset_pages(obj);
		obj->ops->put_pages(obj, pages);

		mutex_unlock(&obj->mm.lock);

		page_sizes = donor->mm.page_sizes.phys;
		pages = __i915_gem_object_unset_pages(donor);
	}

	if (obj->ops->release)
		obj->ops->release(obj);

	/* We need still need a little special casing for shmem */
	if (obj->base.filp)
		fput(fetch_and_zero(&obj->base.filp));
	else if (donor->base.filp) {
		atomic_long_inc(&donor->base.filp->f_count);
		obj->base.filp = donor->base.filp;
	}

	obj->base.size = donor->base.size;
	obj->mm.region = intel_memory_region_get(mem);
	obj->flags = donor->flags;
	obj->ops = donor->ops;
	obj->cache_level = donor->cache_level;
	obj->cache_coherent = donor->cache_coherent;
	obj->cache_dirty = donor->cache_dirty;

	list_replace_init(&donor->mm.blocks, &obj->mm.blocks);

	mutex_lock(&mem->objects.lock);
	list_add_tail(&obj->mm.region_link, &mem->objects.list);
	mutex_unlock(&mem->objects.lock);

	/* set pages after migrated */
	if (pages) {
		mutex_lock(&obj->mm.lock);
		__i915_gem_object_set_pages(obj, pages, page_sizes);
		mutex_unlock(&obj->mm.lock);
	}

	GEM_BUG_ON(i915_gem_object_has_pages(donor));
	GEM_BUG_ON(i915_gem_object_has_pinned_pages(donor));

err_put_donor:
	i915_gem_object_put(donor);
	if (i915_gem_object_has_pinned_pages(obj))
		i915_gem_object_unpin_pages(obj);

	return err;
}

static void __i915_gem_free_object_rcu(struct rcu_head *head)
{
	struct drm_i915_gem_object *obj =
		container_of(head, typeof(*obj), rcu);
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	dma_resv_fini(&obj->base._resv);
	i915_gem_object_free(obj);

	GEM_BUG_ON(!atomic_read(&i915->mm.free_count));
	atomic_dec(&i915->mm.free_count);
}

struct object_memcpy_info {
	struct drm_i915_gem_object *obj;
	struct dma_fence *fence;
	intel_wakeref_t wakeref;
	bool write;
	int clflush;
	struct page *page;
	void *vaddr;
	void *(*get_vaddr)(struct object_memcpy_info *info,
			   unsigned long idx);
	void (*put_vaddr)(struct object_memcpy_info *info);
};

static
void *lmem_get_vaddr(struct object_memcpy_info *info, unsigned long idx)
{
	info->vaddr = i915_gem_object_lmem_io_map_page(info->obj, idx);
	return info->vaddr;
}

static
void lmem_put_vaddr(struct object_memcpy_info *info)
{
	io_mapping_unmap(info->vaddr);
}

static
void *smem_get_vaddr(struct object_memcpy_info *info, unsigned long idx)
{
	info->page = i915_gem_object_get_page(info->obj, (unsigned int)idx);
	info->vaddr = kmap(info->page);
	if (info->clflush & CLFLUSH_BEFORE)
		drm_clflush_virt_range(info->vaddr, PAGE_SIZE);
	return info->vaddr;
}

static
void smem_put_vaddr(struct object_memcpy_info *info)
{
	if (info->clflush & CLFLUSH_AFTER)
		drm_clflush_virt_range(info->vaddr, PAGE_SIZE);
	kunmap(info->page);
}

static int
i915_gem_object_prepare_memcpy(struct drm_i915_gem_object *obj,
			       struct object_memcpy_info *info,
			       bool write)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	int ret;

	ret = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE,
				   MAX_SCHEDULE_TIMEOUT);
	if (ret)
		return ret;

	ret = i915_gem_object_try_pin_pages(obj);
	if (ret)
		return ret;

	if (i915_gem_object_is_lmem(obj)) {
		if (!i915_gem_object_trylock(obj)) {
			i915_gem_object_unpin_pages(obj);
			return -EAGAIN;
		}
		ret = i915_gem_object_try_set_to_wc_domain(obj, write);
		if (!ret) {
			info->fence = i915_gem_object_lock_fence(obj);
			if (!info->fence)
				ret = -ENOMEM;
		}
		i915_gem_object_unlock(obj);
		if (!ret) {
			info->wakeref =
				intel_runtime_pm_get(&i915->runtime_pm);
			info->get_vaddr = lmem_get_vaddr;
			info->put_vaddr = lmem_put_vaddr;
		}
	} else {
		if (write)
			ret = i915_gem_object_trylock_prepare_write(obj,
							    &info->clflush);
		else
			ret = i915_gem_object_trylock_prepare_read(obj,
							   &info->clflush);

		if (!ret) {
			info->fence = i915_gem_object_lock_fence(obj);
			i915_gem_object_finish_access(obj);
			if (info->fence) {
				info->get_vaddr = smem_get_vaddr;
				info->put_vaddr = smem_put_vaddr;
			} else {
				ret = -ENOMEM;
			}
		}
	}

	if (!ret) {
		info->obj = obj;
		info->write = write;
	} else {
		i915_gem_object_unpin_pages(obj);
	}

	return ret;
}

static void
i915_gem_object_finish_memcpy(struct object_memcpy_info *info)
{
	struct drm_i915_private *i915 = to_i915(info->obj->base.dev);

	if (i915_gem_object_is_lmem(info->obj)) {
		intel_runtime_pm_put(&i915->runtime_pm, info->wakeref);
	} else {
		if (info->write) {
			i915_gem_object_flush_frontbuffer(info->obj,
							  ORIGIN_CPU);
			info->obj->mm.dirty = true;
		}
	}
	i915_gem_object_unlock_fence(info->obj, info->fence);

	i915_gem_object_unpin_pages(info->obj);
}

int i915_gem_object_memcpy(struct drm_i915_gem_object *dst,
			   struct drm_i915_gem_object *src)
{
	struct object_memcpy_info sinfo, dinfo;
	void *svaddr, *dvaddr;
	unsigned long npages;
	int i, ret;

	ret = i915_gem_object_prepare_memcpy(src, &sinfo, false);
	if (ret)
		return ret;

	ret = i915_gem_object_prepare_memcpy(dst, &dinfo, true);
	if (ret)
		goto finish_src;

	npages = src->base.size / PAGE_SIZE;
	for (i = 0; i < npages; i++) {
		svaddr = sinfo.get_vaddr(&sinfo, i);
		dvaddr = dinfo.get_vaddr(&dinfo, i);

		/* a performance optimization */
		if (!i915_gem_object_is_lmem(src) ||
		    !i915_memcpy_from_wc(dvaddr, svaddr, PAGE_SIZE))
			memcpy(dvaddr, svaddr, PAGE_SIZE);

		dinfo.put_vaddr(&dinfo);
		sinfo.put_vaddr(&sinfo);
	}

	i915_gem_object_finish_memcpy(&dinfo);
finish_src:
	i915_gem_object_finish_memcpy(&sinfo);

	return ret;
}

static void __i915_gem_free_objects(struct drm_i915_private *i915,
				    struct llist_node *freed)
{
	struct drm_i915_gem_object *obj, *on;
	intel_wakeref_t wakeref;

	wakeref = intel_runtime_pm_get(&i915->runtime_pm);
	llist_for_each_entry_safe(obj, on, freed, freed) {
		struct i915_mmap_offset *mmo, *mn;

		trace_i915_gem_object_destroy(obj);

		if (!list_empty(&obj->vma.list)) {
			struct i915_vma *vma;

			/*
			 * Note that the vma keeps an object reference while
			 * it is active, so it *should* not sleep while we
			 * destroy it. Our debug code errs insits it *might*.
			 * For the moment, play along.
			 */
			spin_lock(&obj->vma.lock);
			while ((vma = list_first_entry_or_null(&obj->vma.list,
							       struct i915_vma,
							       obj_link))) {
				GEM_BUG_ON(vma->obj != obj);
				spin_unlock(&obj->vma.lock);

				__i915_vma_put(vma);

				spin_lock(&obj->vma.lock);
			}
			spin_unlock(&obj->vma.lock);
		}

		i915_gem_object_release_mmap(obj);

		rbtree_postorder_for_each_entry_safe(mmo, mn,
						     &obj->mmo.offsets,
						     offset) {
			drm_vma_offset_remove(obj->base.dev->vma_offset_manager,
					      &mmo->vma_node);
			kfree(mmo);
		}
		obj->mmo.offsets = RB_ROOT;

		GEM_BUG_ON(atomic_read(&obj->bind_count));
		GEM_BUG_ON(obj->userfault_count);
		GEM_BUG_ON(!list_empty(&obj->lut_list));
		GEM_BUG_ON(!list_empty(&obj->client_list));

		atomic_set(&obj->mm.pages_pin_count, 0);
		__i915_gem_object_put_pages(obj);
		GEM_BUG_ON(i915_gem_object_has_pages(obj));
		bitmap_free(obj->bit_17);

		if (obj->base.import_attach)
			drm_prime_gem_destroy(&obj->base, NULL);

		drm_gem_free_mmap_offset(&obj->base);

		if (obj->ops->release)
			obj->ops->release(obj);

		kfree(obj->mm.placements);

		/* But keep the pointer alive for RCU-protected lookups */
		call_rcu(&obj->rcu, __i915_gem_free_object_rcu);
	}
	intel_runtime_pm_put(&i915->runtime_pm, wakeref);
}

void i915_gem_flush_free_objects(struct drm_i915_private *i915)
{
	struct llist_node *freed = llist_del_all(&i915->mm.free_list);

	if (unlikely(freed))
		__i915_gem_free_objects(i915, freed);
}

static void __i915_gem_free_work(struct work_struct *work)
{
	struct drm_i915_private *i915 =
		container_of(work, struct drm_i915_private, mm.free_work);

	i915_gem_flush_free_objects(i915);
}

void i915_gem_free_object(struct drm_gem_object *gem_obj)
{
	struct drm_i915_gem_object *obj = to_intel_bo(gem_obj);
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	GEM_BUG_ON(i915_gem_object_is_framebuffer(obj));

	/*
	 * If object had been swapped out, free the hidden object.
	 */
	if (obj->swapto) {
		GEM_BUG_ON(!i915->params.enable_eviction);
		i915_gem_free_object(&obj->swapto->base);
		obj->swapto = NULL;
	}

	/*
	 * Before we free the object, make sure any pure RCU-only
	 * read-side critical sections are complete, e.g.
	 * i915_gem_busy_ioctl(). For the corresponding synchronized
	 * lookup see i915_gem_object_lookup_rcu().
	 */
	atomic_inc(&i915->mm.free_count);

	/*
	 * This serializes freeing with the shrinker. Since the free
	 * is delayed, first by RCU then by the workqueue, we want the
	 * shrinker to be able to free pages of unreferenced objects,
	 * or else we may oom whilst there are plenty of deferred
	 * freed objects.
	 */
	i915_gem_object_make_unshrinkable(obj);

	/*
	 * Since we require blocking on struct_mutex to unbind the freed
	 * object from the GPU before releasing resources back to the
	 * system, we can not do that directly from the RCU callback (which may
	 * be a softirq context), but must instead then defer that work onto a
	 * kthread. We use the RCU callback rather than move the freed object
	 * directly onto the work queue so that we can mix between using the
	 * worker and performing frees directly from subsequent allocations for
	 * crude but effective memory throttling.
	 */
	if (llist_add(&obj->freed, &i915->mm.free_list))
		queue_work(i915->wq, &i915->mm.free_work);
}

static bool gpu_write_needs_clflush(struct drm_i915_gem_object *obj)
{
	return !(obj->cache_level == I915_CACHE_NONE ||
		 obj->cache_level == I915_CACHE_WT);
}

void
i915_gem_object_flush_write_domain(struct drm_i915_gem_object *obj,
				   unsigned int flush_domains)
{
	struct i915_vma *vma;

	assert_object_held(obj);

	if (!(obj->write_domain & flush_domains))
		return;

	switch (obj->write_domain) {
	case I915_GEM_DOMAIN_GTT:
		spin_lock(&obj->vma.lock);
		for_each_ggtt_vma(vma, obj) {
			if (i915_vma_unset_ggtt_write(vma))
				intel_gt_flush_ggtt_writes(vma->vm->gt);
		}
		spin_unlock(&obj->vma.lock);

		i915_gem_object_flush_frontbuffer(obj, ORIGIN_CPU);
		break;

	case I915_GEM_DOMAIN_WC:
		wmb();
		break;

	case I915_GEM_DOMAIN_CPU:
		i915_gem_clflush_object(obj, I915_CLFLUSH_SYNC);
		break;

	case I915_GEM_DOMAIN_RENDER:
		if (gpu_write_needs_clflush(obj))
			obj->cache_dirty = true;
		break;
	}

	obj->write_domain = 0;
}

void __i915_gem_object_flush_frontbuffer(struct drm_i915_gem_object *obj,
					 enum fb_op_origin origin)
{
	struct intel_frontbuffer *front;

	front = __intel_frontbuffer_get(obj);
	if (front) {
		intel_frontbuffer_flush(front, origin);
		intel_frontbuffer_put(front);
	}
}

void __i915_gem_object_invalidate_frontbuffer(struct drm_i915_gem_object *obj,
					      enum fb_op_origin origin)
{
	struct intel_frontbuffer *front;

	front = __intel_frontbuffer_get(obj);
	if (front) {
		intel_frontbuffer_invalidate(front, origin);
		intel_frontbuffer_put(front);
	}
}

void i915_gem_init__objects(struct drm_i915_private *i915)
{
	INIT_WORK(&i915->mm.free_work, __i915_gem_free_work);
}

static void i915_global_objects_shrink(void)
{
	kmem_cache_shrink(global.slab_objects);
}

static void i915_global_objects_exit(void)
{
	kmem_cache_destroy(global.slab_objects);
}

static struct i915_global_object global = { {
	.shrink = i915_global_objects_shrink,
	.exit = i915_global_objects_exit,
} };

int __init i915_global_objects_init(void)
{
	global.slab_objects =
		KMEM_CACHE(drm_i915_gem_object, SLAB_HWCACHE_ALIGN);
	if (!global.slab_objects)
		return -ENOMEM;

	i915_global_register(&global.base);
	return 0;
}

#define BLT_WINDOW_SZ SZ_4M
static int i915_alloc_vm_range(struct i915_vma *vma)
{
	int err;

	err = vma->vm->allocate_va_range(vma->vm,
					 vma->node.start, vma->size);
	if (err) {
		DRM_ERROR("allocate_va_range failed. %d\n", err);
		return err;
	}
	set_bit(I915_VMA_ALLOC_BIT, __i915_vma_flags(vma));
	return 0;
}

static inline void i915_insert_vma_pages(struct i915_vma *vma, bool is_lmem)
{
	enum i915_cache_level cache_level = I915_CACHE_NONE;

	vma->vm->insert_entries(vma->vm, vma, cache_level,
				is_lmem ? PTE_LM : 0);
	wmb();
}

static struct i915_vma *
i915_window_vma_init(struct drm_i915_private *i915,
		     struct intel_memory_region *mem)
{
	struct intel_context *ce = i915->engine[BCS0]->evict_context;
	struct i915_address_space *vm = ce->vm;
	struct i915_vma *vma;
	int ret;

	vma = i915_alloc_window_vma(i915, vm, BLT_WINDOW_SZ,
				    mem->min_page_size);
	if (IS_ERR(vma)) {
		DRM_ERROR("window vma alloc failed(%ld)\n", PTR_ERR(vma));
		return vma;
	}

	vma->pages = kmalloc(sizeof(*vma->pages), GFP_KERNEL);
	if (!vma->pages) {
		ret = -ENOMEM;
		DRM_ERROR("page alloc failed. %d", ret);
		goto err_page;
	}

	ret = sg_alloc_table(vma->pages, BLT_WINDOW_SZ / PAGE_SIZE,
			     GFP_KERNEL);
	if (ret) {
		DRM_ERROR("sg alloc table failed(%d)", ret);
		goto err_sg_table;
	}

	mutex_lock(&vm->mutex);
	ret = drm_mm_insert_node_in_range(&vm->mm, &vma->node,
					  BLT_WINDOW_SZ, BLT_WINDOW_SZ,
					  I915_COLOR_UNEVICTABLE,
					  0, vm->total,
					  DRM_MM_INSERT_LOW);
	mutex_unlock(&vm->mutex);
	if (ret) {
		DRM_ERROR("drm_mm_insert_node_in_range failed. %d\n", ret);
		goto err_mm_node;
	}

	ret = i915_alloc_vm_range(vma);
	if (ret) {
		DRM_ERROR("src: Page table alloc failed(%d)\n", ret);
		goto err_alloc;
	}

	return vma;

err_alloc:
	mutex_lock(&vm->mutex);
	drm_mm_remove_node(&vma->node);
	mutex_unlock(&vm->mutex);
err_mm_node:
	sg_free_table(vma->pages);
err_sg_table:
	kfree(vma->pages);
err_page:
	i915_destroy_window_vma(vma);

	return ERR_PTR(ret);
}

static void i915_window_vma_teardown(struct i915_vma *vma)
{
	vma->vm->clear_range(vma->vm, vma->node.start, vma->size);
	drm_mm_remove_node(&vma->node);
	sg_free_table(vma->pages);
	kfree(vma->pages);
	i915_destroy_window_vma(vma);
}

int i915_setup_blt_windows(struct drm_i915_private *i915)
{
	struct intel_memory_region *lmem_region =
		intel_memory_region_by_type(i915, INTEL_MEMORY_LOCAL);
	struct intel_memory_region *smem_region =
		intel_memory_region_by_type(i915, INTEL_MEMORY_SYSTEM);
	struct i915_vma *lmem[2];
	struct i915_vma *smem[2];
	int ret, i;

	if (!i915->engine[BCS0]) {
		DRM_DEBUG("No BCS0 engine, hence blt evict is not setup\n");
		return 0;
	}

	mutex_init(&i915->mm.window_mutex);
	for (i = 0; i < ARRAY_SIZE(lmem); i++) {
		lmem[i] = i915_window_vma_init(i915, lmem_region);
		if (IS_ERR_OR_NULL(lmem[i])) {
			ret = PTR_ERR(lmem[i]);
			DRM_ERROR("Err for lmem[%d]. %d\n", i, ret);
			if (i--)
				for (; i >= 0; i--)
					i915_window_vma_teardown(lmem[i]);
			return ret;
		}
		i915->mm.lmem_window[i] = lmem[i];
		GEM_BUG_ON(!i915->mm.lmem_window[i]);
	}

	for (i = 0; i < ARRAY_SIZE(smem); i++) {
		smem[i] = i915_window_vma_init(i915, smem_region);
		if (IS_ERR_OR_NULL(smem[i])) {
			ret = PTR_ERR(smem[i]);
			DRM_ERROR("Err for smem[%d]. %d\n", i, ret);
			if (i--)
				for (; i >= 0; i--)
					i915_window_vma_teardown(smem[i]);
			for (i = 0; i < ARRAY_SIZE(lmem); i++)
				i915_window_vma_teardown(lmem[i]);
			return ret;
		}
		i915->mm.smem_window[i] = smem[i];
		GEM_BUG_ON(!i915->mm.smem_window[i]);
	}

	return 0;
}

void i915_teardown_blt_windows(struct drm_i915_private *i915)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(i915->mm.lmem_window); i++) {
		if (!i915->mm.lmem_window[i])
			continue;
		i915_window_vma_teardown(i915->mm.lmem_window[i]);
	}
	for (i = 0; i < ARRAY_SIZE(i915->mm.smem_window); i++) {
		if (!i915->mm.smem_window[i])
			continue;
		i915_window_vma_teardown(i915->mm.smem_window[i]);
	}
	mutex_destroy(&i915->mm.window_mutex);
}

static int i915_window_blt_copy_prepare_obj(struct drm_i915_gem_object *obj)
{
	int ret;

	ret = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE,
				   MAX_SCHEDULE_TIMEOUT);
	if (ret)
		return ret;

	return i915_gem_object_try_pin_pages(obj);
}

static int
i915_window_blt_copy_batch_prepare(struct i915_request *rq,
				   struct i915_vma *src,
				   struct i915_vma *dst, size_t size)
{
	u32 *cmd;

	GEM_BUG_ON(size > BLT_WINDOW_SZ);
	cmd = intel_ring_begin(rq, 10);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	GEM_BUG_ON(size >> PAGE_SHIFT > S16_MAX);
	GEM_BUG_ON(INTEL_GEN(rq->engine->i915) < 9);

	*cmd++ = GEN9_XY_FAST_COPY_BLT_CMD | (10 - 2);
	*cmd++ = BLT_DEPTH_32 | PAGE_SIZE;
	*cmd++ = 0;
	*cmd++ = size >> PAGE_SHIFT << 16 | PAGE_SIZE / 4;
	*cmd++ = lower_32_bits(dst->node.start);
	*cmd++ = upper_32_bits(dst->node.start);
	*cmd++ = 0;
	*cmd++ = PAGE_SIZE;
	*cmd++ = lower_32_bits(src->node.start);
	*cmd++ = upper_32_bits(src->node.start);
	intel_ring_advance(rq, cmd);

	return 0;
}

int i915_window_blt_copy(struct drm_i915_gem_object *dst,
			 struct drm_i915_gem_object *src)
{
	struct drm_i915_private *i915 = to_i915(src->base.dev);
	struct intel_context *ce = i915->engine[BCS0]->evict_context;
	bool src_is_lmem = i915_gem_object_is_lmem(src);
	bool dst_is_lmem = i915_gem_object_is_lmem(dst);
	struct scatterlist *last_sgl;
	struct i915_vma *src_vma, *dst_vma;
	struct i915_request *rq;
	u64 cur_win_sz, blt_copied, offset;
	int err = -EINVAL;
	long timeout;
	u32 size;

	src_vma = src_is_lmem ? i915->mm.lmem_window[0] :
				i915->mm.smem_window[0];
	dst_vma = dst_is_lmem ? i915->mm.lmem_window[1] :
				i915->mm.smem_window[1];

	if (!src_vma || !dst_vma)
		return -EINVAL;

	blt_copied = 0;

	err = i915_window_blt_copy_prepare_obj(src);
	if (err)
		return err;

	err = i915_window_blt_copy_prepare_obj(dst);
	if (err) {
		i915_gem_object_unpin_pages(src);
		return err;
	}

	mutex_lock(&i915->mm.window_mutex);
	src_vma->obj = src;
	dst_vma->obj = dst;
	do {
		cur_win_sz = min_t(u64, BLT_WINDOW_SZ,
				   (src->base.size - blt_copied));
		offset = blt_copied >> PAGE_SHIFT;
		size = ALIGN(cur_win_sz, src->mm.region->min_page_size) >>
		       PAGE_SHIFT;
		intel_partial_pages_for_sg_table(src, src_vma->pages, offset,
						 size, &last_sgl);

		/*
		 * Insert pages into vm, expects the pages to the full
		 * length of VMA. But we may have the pages of <= vma_size.
		 * Hence altering the vma size to match the total size of
		 * the pages attached.
		 */
		src_vma->size = size << PAGE_SHIFT;
		i915_insert_vma_pages(src_vma, src_is_lmem);
		sg_unmark_end(last_sgl);

		/*
		 * Source obj size could be smaller than the dst obj size,
		 * due to the varying min_page_size of the mem regions the
		 * obj belongs to. But when we insert the pages into vm,
		 * the total size of the pages supposed to be multiples of
		 * the min page size of that mem region.
		 */
		size = ALIGN(cur_win_sz, dst->mm.region->min_page_size) >>
		       PAGE_SHIFT;
		intel_partial_pages_for_sg_table(dst, dst_vma->pages, offset,
						 size, &last_sgl);

		dst_vma->size = size << PAGE_SHIFT;
		i915_insert_vma_pages(dst_vma, dst_is_lmem);
		sg_unmark_end(last_sgl);

		rq = intel_context_try_create_request(ce);
		if (IS_ERR(rq)) {
			err = PTR_ERR(rq);
			break;
		}
		if (rq->engine->emit_init_breadcrumb) {
			err = rq->engine->emit_init_breadcrumb(rq);
			if (unlikely(err)) {
				DRM_ERROR("init_breadcrumb failed. %d\n", err);
				break;
			}
		}
		err = i915_window_blt_copy_batch_prepare(rq, src_vma, dst_vma,
							 cur_win_sz);
		if (err) {
			DRM_ERROR("Batch preparation failed. %d\n", err);
			i915_request_set_error_once(rq, err);
			__i915_request_skip(rq);
		}

		i915_request_get(rq);
		i915_request_add(rq);

		timeout = i915_request_wait(rq, 0, MAX_SCHEDULE_TIMEOUT);
		if (timeout < 0) {
			DRM_ERROR("BLT Request is not completed. %ld\n",
				  timeout);
			err = timeout;
			i915_request_put(rq);
			break;
		}

		blt_copied += cur_win_sz;
		err = 0;
		i915_request_put(rq);
		flush_work(&i915->engine[BCS0]->retire_work);
	} while (src->base.size != blt_copied);

	src_vma->size = BLT_WINDOW_SZ;
	dst_vma->size = BLT_WINDOW_SZ;
	src_vma->obj = NULL;
	dst_vma->obj = NULL;
	mutex_unlock(&i915->mm.window_mutex);

	dst->mm.dirty = true;
	i915_gem_object_unpin_pages(src);
	i915_gem_object_unpin_pages(dst);

	return err;
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/huge_gem_object.c"
#include "selftests/huge_pages.c"
#include "selftests/i915_gem_object.c"
#include "selftests/i915_gem_coherency.c"
#endif
