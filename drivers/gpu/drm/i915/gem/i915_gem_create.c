// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "gem/i915_gem_ioctls.h"
#include "gem/i915_gem_lmem.h"
#include "gem/i915_gem_object_blt.h"
#include "gem/i915_gem_region.h"

#include "i915_drv.h"
#include "i915_user_extensions.h"

static u32 max_page_size(struct intel_memory_region **placements,
			 int n_placements)
{
	u32 max_page_size = 0;
	int i;

	for (i = 0; i < n_placements; ++i) {
		max_page_size = max_t(u32, max_page_size,
				      placements[i]->min_page_size);
	}

	GEM_BUG_ON(!max_page_size);
	return max_page_size;
}

static int
i915_gem_create(struct drm_file *file,
		struct intel_memory_region **placements,
		int n_placements,
		u64 *size_p,
		u32 *handle_p)
{
	struct drm_i915_gem_object *obj;
	u32 handle;
	u64 size;
	int ret;

	size = round_up(*size_p, max_page_size(placements, n_placements));
	if (size == 0)
		return -EINVAL;

	/* For most of the ABI (e.g. mmap) we think in system pages */
	GEM_BUG_ON(!IS_ALIGNED(size, PAGE_SIZE));

	/* Allocate the new object */
	obj = i915_gem_object_create_region(placements[0], size, 0);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	if (i915_gem_object_is_lmem(obj)) {
		struct intel_gt *gt = obj->mm.region->gt;
		struct intel_context *ce = gt->engine[BCS0]->blitter_context;

		/*
		 * XXX: We really want to move this to get_pages(), but we
		 * require grabbing the BKL for the blitting operation which is
		 * annoying. In the pipeline is support for async get_pages()
		 * which should fit nicely for this. Also note that the actual
		 * clear should be done async(we currently do an object_wait
		 * which is pure garbage), we just need to take care if
		 * userspace opts of implicit sync for the execbuf, to avoid any
		 * potential info leak.
		 */

retry:
		ret = i915_gem_object_fill_blt(obj, ce, 0);
		if (ret == -EINTR)
			goto retry;
		if (ret) {
			/*
			 * XXX: Post the error to where we would normally gather
			 * and clear the pages. This better reflects the final
			 * uapi behaviour, once we are at the point where we can
			 * move the clear worker to get_pages().
			 */
			i915_gem_object_unbind(obj, I915_GEM_OBJECT_UNBIND_ACTIVE);
			__i915_gem_object_put_pages(obj);
			obj->mm.gem_create_posted_err = ret;
			goto handle_create;
		}

		/*
		 * XXX: Occasionally i915_gem_object_wait() called inside
		 * i915_gem_object_set_to_cpu_domain() get interrupted
		 * and return -ERESTARTSYS, this will cause go clearing
		 * code below and also set the gem_create_posted_err.
		 * moreover, the clearing sometimes fails because the
		 * object is still pinned by the blitter clearing code.
		 * this makes us to have an object with or without lmem
		 * pages, and with gem_create_posted_err = -ERESTARTSYS.
		 * Under lmem pressure, if the object has pages, we might
		 * swap out this object to smem. Next when user space
		 * code use this object in gem_execbuf() call, get_pages()
		 * operation will return -ERESTARTSYS error code, which
		 * causes user space code to fail.
		 *
		 * To avoid this problem, we add a retry logic when this
		 * -ERESTARTSYS error code is caught.
		 */
		i915_gem_object_lock(obj);
retry2:
		ret = i915_gem_object_set_to_cpu_domain(obj, false);
		if (ret == -ERESTARTSYS)
			goto retry2;
		i915_gem_object_unlock(obj);
		if (ret) {
			i915_gem_object_unbind(obj, I915_GEM_OBJECT_UNBIND_ACTIVE);
			__i915_gem_object_put_pages(obj);
			obj->mm.gem_create_posted_err = ret;
			goto handle_create;
		}
	}

handle_create:
	obj->mm.placements = placements;
	obj->mm.n_placements = n_placements;

	ret = drm_gem_handle_create(file, &obj->base, &handle);
	/* drop reference from allocate - handle holds it now */
	i915_gem_object_put(obj);
	if (ret)
		return ret;

	*handle_p = handle;
	*size_p = size;
	return 0;
}

int
i915_gem_dumb_create(struct drm_file *file,
		     struct drm_device *dev,
		     struct drm_mode_create_dumb *args)
{
	struct intel_memory_region **placements;
	enum intel_memory_type mem_type;
	int cpp = DIV_ROUND_UP(args->bpp, 8);
	u32 format;
	int ret;

	switch (cpp) {
	case 1:
		format = DRM_FORMAT_C8;
		break;
	case 2:
		format = DRM_FORMAT_RGB565;
		break;
	case 4:
		format = DRM_FORMAT_XRGB8888;
		break;
	default:
		return -EINVAL;
	}

	/* have to work out size/pitch and return them */
	args->pitch = ALIGN(args->width * cpp, 64);

	/* align stride to page size so that we can remap */
	if (args->pitch > intel_plane_fb_max_stride(to_i915(dev), format,
						    DRM_FORMAT_MOD_LINEAR))
		args->pitch = ALIGN(args->pitch, 4096);

	args->size = args->pitch * args->height;

	mem_type = INTEL_MEMORY_SYSTEM;
	if (HAS_LMEM(to_i915(dev)))
		mem_type = INTEL_MEMORY_LOCAL;

	placements = kmalloc(sizeof(struct intel_memory_region *), GFP_KERNEL);
	if (!placements)
		return -ENOMEM;

	placements[0] = intel_memory_region_by_type(to_i915(dev), mem_type);

	ret = i915_gem_create(file,
			      placements, 1,
			      &args->size, &args->handle);
	if (ret)
		kfree(placements);

	return ret;
}

struct create_ext {
	struct drm_i915_private *i915;
	struct intel_memory_region **placements;
	int n_placements;
};

static void repr_placements(char *buf, size_t size,
			    struct intel_memory_region **placements,
			    int n_placements)
{
	int i;

	buf[0] = '\0';

	for (i = 0; i < n_placements; i++) {
		struct intel_memory_region *mr = placements[i];
		int r;

		r = snprintf(buf, size, "\n  %s -> { class: %d, inst: %d }",
			     mr->name, mr->type, mr->instance);
		if (r >= size)
			return;

		buf += r;
		size -= r;
	}
}

static int set_placements(struct drm_i915_gem_object_param *args,
			  struct create_ext *ext_data)
{
	struct drm_i915_private *i915 = ext_data->i915;
	struct drm_i915_gem_memory_class_instance __user *uregions =
		u64_to_user_ptr(args->data);
	struct intel_memory_region **placements;
	u32 mask;
	int i, ret = 0;

	if (args->handle) {
		DRM_DEBUG("Handle should be zero\n");
		ret = -EINVAL;
	}

	if (!args->size) {
		DRM_DEBUG("Size is zero\n");
		ret = -EINVAL;
	}

	if (args->size > ARRAY_SIZE(i915->mm.regions)) {
		DRM_DEBUG("Too many placements\n");
		ret = -EINVAL;
	}

	if (ret)
		return ret;

	placements = kmalloc_array(args->size,
				   sizeof(struct intel_memory_region *),
				   GFP_KERNEL);
	if (!placements)
		return -ENOMEM;

	mask = 0;
	for (i = 0; i < args->size; i++) {
		struct drm_i915_gem_memory_class_instance region;
		struct intel_memory_region *mr;

		if (copy_from_user(&region, uregions, sizeof(region))) {
			ret = -EFAULT;
			goto out_free;
		}

		mr = intel_memory_region_lookup(i915,
						region.memory_class,
						region.memory_instance);
		if (!mr) {
			DRM_DEBUG("Device is missing region { class: %d, inst: %d } at index = %d\n",
				  region.memory_class, region.memory_instance, i);
			ret = -EINVAL;
			goto out_dump;
		}

		if (mask & BIT(mr->id)) {
			DRM_DEBUG("Found duplicate placement %s -> { class: %d, inst: %d } at index = %d\n",
				  mr->name, region.memory_class,
				  region.memory_instance, i);
			ret = -EINVAL;
			goto out_dump;
		}

		placements[i] = mr;
		mask |= BIT(mr->id);

		++uregions;
	}

	if (ext_data->placements) {
		ret = -EINVAL;
		goto out_dump;
	}

	ext_data->placements = placements;
	ext_data->n_placements = args->size;

	return 0;

out_dump:
	if (1) {
		char buf[256];

		if (ext_data->placements) {
			repr_placements(buf,
					sizeof(buf),
					ext_data->placements,
					ext_data->n_placements);
			DRM_DEBUG("Placements were already set in previous SETPARAM. Existing placements: %s\n",
				  buf);
		}

		repr_placements(buf, sizeof(buf), placements, i);
		DRM_DEBUG("New placements(so far validated): %s\n", buf);
	}

out_free:
	kfree(placements);
	return ret;
}

static int __create_setparam(struct drm_i915_gem_object_param *args,
			     struct create_ext *ext_data)
{
	if (!(args->param & I915_OBJECT_PARAM)) {
		DRM_DEBUG("Missing I915_OBJECT_PARAM namespace\n");
		return -EINVAL;
	}

	switch (lower_32_bits(args->param)) {
	case I915_PARAM_MEMORY_REGIONS:
		return set_placements(args, ext_data);
	}

	return -EINVAL;
}

static int create_setparam(struct i915_user_extension __user *base, void *data)
{
	struct drm_i915_gem_create_ext_setparam ext;

	if (copy_from_user(&ext, base, sizeof(ext)))
		return -EFAULT;

	return __create_setparam(&ext.param, data);
}

static const i915_user_extension_fn create_extensions[] = {
	[I915_GEM_CREATE_EXT_SETPARAM] = create_setparam,
};

/**
 * Creates a new mm object and returns a handle to it.
 * @dev: drm device pointer
 * @data: ioctl data blob
 * @file: drm file pointer
 */
int
i915_gem_create_ioctl(struct drm_device *dev, void *data,
		      struct drm_file *file)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct create_ext ext_data = { .i915 = i915 };
	struct drm_i915_gem_create_ext *args = data;
	int ret;

	i915_gem_flush_free_objects(i915);

	ret = i915_user_extensions(u64_to_user_ptr(args->extensions),
				   create_extensions,
				   ARRAY_SIZE(create_extensions),
				   &ext_data);
	if (ret)
		goto err_free;

	if (!ext_data.placements) {
		struct intel_memory_region **placements;
		enum intel_memory_type mem_type = INTEL_MEMORY_SYSTEM;

		placements = kmalloc(sizeof(struct intel_memory_region *),
				     GFP_KERNEL);
		if (!placements)
			return -ENOMEM;

		placements[0] = intel_memory_region_by_type(i915, mem_type);

		ext_data.placements = placements;
		ext_data.n_placements = 1;
	}

	ret = i915_gem_create(file,
			      ext_data.placements,
			      ext_data.n_placements,
			      &args->size, &args->handle);
	if (!ret)
		return 0;

err_free:
	kfree(ext_data.placements);
	return ret;
}
