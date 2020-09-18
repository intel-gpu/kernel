/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2020 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <drm/drm_print.h>

#include <uapi/drm/i915_drm.h>

#include "i915_drv.h"
#include "i915_drm_client.h"
#include "gem/i915_gem_context.h"
#include "gt/intel_engine_user.h"
#include "i915_drv.h"
#include "i915_gem.h"
#include "i915_utils.h"

void i915_drm_clients_init(struct i915_drm_clients *clients)
{
	clients->next_id = 0;
	xa_init_flags(&clients->xarray, XA_FLAGS_ALLOC);
}

static ssize_t
show_client_name(struct device *kdev, struct device_attribute *attr, char *buf)
{
	struct i915_drm_client *client =
		container_of(attr, typeof(*client), attr.name);
	int ret;

	rcu_read_lock();
	ret = snprintf(buf, PAGE_SIZE,
		       READ_ONCE(client->closed) ? "<%s>" : "%s",
		       rcu_dereference(client->name));
	rcu_read_unlock();

	return ret;
}

static ssize_t
show_client_pid(struct device *kdev, struct device_attribute *attr, char *buf)
{
	struct i915_drm_client *client =
		container_of(attr, typeof(*client), attr.pid);
	int ret;

	rcu_read_lock();
	ret = snprintf(buf, PAGE_SIZE,
		       READ_ONCE(client->closed) ? "<%u>" : "%u",
		       pid_nr(rcu_dereference(client->pid)));
	rcu_read_unlock();

	return ret;
}

static u64
pphwsp_busy_add(struct i915_gem_context *ctx, unsigned int class)
{
	struct i915_gem_engines *engines = rcu_dereference(ctx->engines);
	struct i915_gem_engines_iter it;
	struct intel_context *ce;
	u64 total = 0;

	for_each_gem_engine(ce, engines, it) {
		if (ce->engine->uabi_class == class)
			total += ce->stats.runtime.total;
	}

	return total;
}

static ssize_t
show_client_busy(struct device *kdev, struct device_attribute *attr, char *buf)
{
	struct i915_engine_busy_attribute *i915_attr =
		container_of(attr, typeof(*i915_attr), attr);
	unsigned int class = i915_attr->engine_class;
	struct i915_drm_client *client = i915_attr->client;
	u64 total = atomic64_read(&client->past_runtime[class]);
	struct list_head *list = &client->ctx_list;
	struct i915_gem_context *ctx;

	rcu_read_lock();
	list_for_each_entry_rcu(ctx, list, client_link) {
		total += atomic64_read(&ctx->past_runtime[class]);
		total += pphwsp_busy_add(ctx, class);
	}
	rcu_read_unlock();

	total *= RUNTIME_INFO(i915_attr->i915)->cs_timestamp_period_ns;

	return snprintf(buf, PAGE_SIZE, "%llu\n", total);
}

static u64
sw_busy_add(struct i915_gem_context *ctx, unsigned int class)
{
	struct i915_gem_engines *engines = rcu_dereference(ctx->engines);
	u32 period_ns = RUNTIME_INFO(ctx->i915)->cs_timestamp_period_ns;
	struct i915_gem_engines_iter it;
	struct intel_context *ce;
	u64 total = 0;

	for_each_gem_engine(ce, engines, it) {
		struct intel_context_stats *stats;
		unsigned int seq;
		u64 t;

		if (ce->engine->uabi_class != class)
			continue;

		stats = &ce->stats;

		do {
			seq = read_seqbegin(&stats->lock);
			t = ce->stats.runtime.total * period_ns;
			t += __intel_context_get_active_time(ce);
		} while (read_seqretry(&stats->lock, seq));

		total += t;
	}

	return total;
}

static ssize_t
show_client_sw_busy(struct device *kdev,
		    struct device_attribute *attr,
		    char *buf)
{
	struct i915_engine_busy_attribute *i915_attr =
		container_of(attr, typeof(*i915_attr), attr);
	unsigned int class = i915_attr->engine_class;
	struct i915_drm_client *client = i915_attr->client;
	u32 period_ns = RUNTIME_INFO(i915_attr->i915)->cs_timestamp_period_ns;
	u64 total = atomic64_read(&client->past_runtime[class]) * period_ns;
	struct list_head *list = &client->ctx_list;
	struct i915_gem_context *ctx;

	rcu_read_lock();
	list_for_each_entry_rcu(ctx, list, client_link) {
		total += atomic64_read(&ctx->past_runtime[class]) * period_ns +
			 sw_busy_add(ctx, class);
	}
	rcu_read_unlock();

	return snprintf(buf, PAGE_SIZE, "%llu\n", total);
}

/*
 * The objs created by a client which have a possible placement in Local
 * Memory only are accounted. Their sizes are aggregated and presented via
 * this sysfs entry
 */
static ssize_t show_client_created_devm_bytes(struct device *kdev,
					      struct device_attribute *attr,
					      char *buf)
{
	struct i915_drm_client *client =
		container_of(attr, typeof(*client), attr.created_devm_bytes);

	return snprintf(buf, PAGE_SIZE, "%llu\n",
			atomic64_read(&client->created_devm_bytes));
}

/*
 * The objs imported by a client via PRIME/FLINK which have a possible
 * placement in Local  Memory only are accounted. Their sizes are aggregated
 * and presented via this sysfs entry
 */
static ssize_t show_client_imported_devm_bytes(struct device *kdev,
					       struct device_attribute *attr,
					       char *buf)
{
	struct i915_drm_client *client =
		container_of(attr, typeof(*client), attr.imported_devm_bytes);

	return snprintf(buf, PAGE_SIZE, "%llu\n",
			atomic64_read(&client->imported_devm_bytes));
}

static const char * const uabi_class_names[] = {
	[I915_ENGINE_CLASS_RENDER] = "0",
	[I915_ENGINE_CLASS_COPY] = "1",
	[I915_ENGINE_CLASS_VIDEO] = "2",
	[I915_ENGINE_CLASS_VIDEO_ENHANCE] = "3",
};

static int
__client_register_sysfs_busy(struct i915_drm_client *client)
{
	struct i915_drm_clients *clients = client->clients;
	struct drm_i915_private *i915 =
		container_of(clients, typeof(*i915), clients);
	bool sw_stats = i915->caps.scheduler &
			I915_SCHEDULER_CAP_ENGINE_BUSY_STATS;
	unsigned int i;
	int ret = 0;

	if (!HAS_LOGICAL_RING_CONTEXTS(i915))
		return 0;

	client->busy_root = kobject_create_and_add("busy", client->root);
	if (!client->busy_root)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(uabi_class_names); i++) {
		struct i915_engine_busy_attribute *i915_attr =
			&client->attr.busy[i];
		struct device_attribute *attr = &i915_attr->attr;

		if (!intel_engine_lookup_user(i915, i, 0))
			continue;

		i915_attr->client = client;
		i915_attr->i915 = i915;
		i915_attr->engine_class = i;

		sysfs_attr_init(&attr->attr);

		attr->attr.name = uabi_class_names[i];
		attr->attr.mode = 0444;
		attr->show = sw_stats ?
			     show_client_sw_busy : show_client_busy;

		ret = sysfs_create_file(client->busy_root,
					(struct attribute *)attr);
		if (ret)
			goto out;
	}

out:
	if (ret)
		kobject_put(client->busy_root);

	return ret;
}

static void __client_unregister_sysfs_busy(struct i915_drm_client *client)
{
	kobject_put(fetch_and_zero(&client->busy_root));
}

int i915_drm_client_add_bo_sz(struct drm_file *file,
			      struct drm_i915_gem_object *obj)
{
	struct drm_i915_file_private *fpriv = file->driver_priv;
	struct i915_drm_client *client = fpriv->client;
	struct i915_drm_client_bo *client_bo;
	struct intel_memory_region *placement;
	int i;

	for (i = 0; i < obj->mm.n_placements; i++) {
		placement = obj->mm.placements[i];

		if (placement->type != INTEL_MEMORY_LOCAL)
			continue;

		client_bo = kzalloc(sizeof(*client_bo), GFP_KERNEL);
		if (!client_bo)
			return -ENOMEM;

		client_bo->client = client;

		/* only objs which can reside in LOCAL MEMORY are considered */
		if (obj->base.dma_buf) {
			atomic64_add(obj->base.size,
				     &client->imported_devm_bytes);
			client_bo->shared = true;
		} else {
			atomic64_add(obj->base.size,
				     &client->created_devm_bytes);
		}

		i915_gem_object_lock(obj);
		list_add(&client_bo->link, &obj->client_list);
		i915_gem_object_unlock(obj);
		break;
	}

	return 0;
}

void i915_drm_client_del_bo_sz(struct drm_file *file,
			       struct drm_i915_gem_object *obj)
{
	struct drm_i915_file_private *fpriv = file->driver_priv;
	struct i915_drm_client *client = fpriv->client;
	struct i915_drm_client_bo *client_bo, *cn;

	assert_object_held(obj);

	list_for_each_entry_safe(client_bo, cn, &obj->client_list, link) {
		if (client_bo->client != client)
			continue;

		if (client_bo->shared)
			atomic64_sub(obj->base.size,
				     &client->imported_devm_bytes);
		else
			atomic64_sub(obj->base.size,
				     &client->created_devm_bytes);

		list_del(&client_bo->link);
		kfree(client_bo);
		break;
	}
}

static int
__client_register_sysfs_memory_stats(struct i915_drm_client *client)
{
	const struct {
		const char *name;
		struct device_attribute *attr;
		ssize_t (*show)(struct device *dev,
				struct device_attribute *attr,
				char *buf);
	} files[] = {
		{ "created_bytes", &client->attr.created_devm_bytes,
				   show_client_created_devm_bytes },
		{ "imported_bytes", &client->attr.imported_devm_bytes,
				    show_client_imported_devm_bytes },
	};
	unsigned int i;
	int ret;

	client->devm_stats_root =
		kobject_create_and_add("total_device_memory_buffer_objects",
				       client->root);
	if (!client->devm_stats_root)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		struct device_attribute *attr = files[i].attr;

		sysfs_attr_init(&attr->attr);

		attr->attr.name = files[i].name;
		attr->attr.mode = 0444;
		attr->show = files[i].show;

		ret = sysfs_create_file(client->devm_stats_root,
					(struct attribute *)attr);
		if (ret)
			goto out;
	}
out:
	if (ret)
		kobject_put(client->devm_stats_root);

	return ret;
}

static void
__client_unregister_sysfs_memory_stats(struct i915_drm_client *client)
{
	kobject_put(fetch_and_zero(&client->devm_stats_root));
}

static int
__client_register_sysfs(struct i915_drm_client *client)
{
	const struct {
		const char *name;
		struct device_attribute *attr;
		ssize_t (*show)(struct device *dev,
				struct device_attribute *attr,
				char *buf);
	} files[] = {
		{ "name", &client->attr.name, show_client_name },
		{ "pid", &client->attr.pid, show_client_pid },
	};
	unsigned int i;
	char buf[16];
	int ret;

	ret = scnprintf(buf, sizeof(buf), "%u", client->id);
	if (ret == sizeof(buf))
		return -EINVAL;

	client->root = kobject_create_and_add(buf, client->clients->root);
	if (!client->root)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		struct device_attribute *attr = files[i].attr;

		sysfs_attr_init(&attr->attr);

		attr->attr.name = files[i].name;
		attr->attr.mode = 0444;
		attr->show = files[i].show;

		ret = sysfs_create_file(client->root, (struct attribute *)attr);
		if (ret)
			goto out;
	}

	ret = __client_register_sysfs_busy(client);
	if (ret)
		goto out;

	ret = __client_register_sysfs_memory_stats(client);

out:
	if (ret)
		kobject_put(client->root);

	return ret;
}

static void __client_unregister_sysfs(struct i915_drm_client *client)
{
	__client_unregister_sysfs_busy(client);
	__client_unregister_sysfs_memory_stats(client);

	kobject_put(fetch_and_zero(&client->root));
}

static int
__i915_drm_client_register(struct i915_drm_client *client,
			   struct task_struct *task)
{
	struct i915_drm_clients *clients = client->clients;
	char *name;
	int ret;

	name = kstrdup(task->comm, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	rcu_assign_pointer(client->pid, get_task_pid(task, PIDTYPE_PID));
	rcu_assign_pointer(client->name, name);

	if (!clients->root)
		return 0; /* intel_fbdev_init registers a client before sysfs */

	ret = __client_register_sysfs(client);
	if (ret)
		goto err_sysfs;

	return 0;

err_sysfs:
	put_pid(rcu_replace_pointer(client->pid, NULL, true));
	kfree(rcu_replace_pointer(client->name, NULL, true));

	return ret;
}

static void
__i915_drm_client_unregister(struct i915_drm_client *client)
{
	__client_unregister_sysfs(client);

	put_pid(rcu_replace_pointer(client->pid, NULL, true));
	kfree(rcu_replace_pointer(client->name, NULL, true));
}

struct i915_drm_client *
i915_drm_client_add(struct i915_drm_clients *clients, struct task_struct *task)
{
	struct i915_drm_client *client;
	int ret;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	kref_init(&client->kref);
	mutex_init(&client->update_lock);
	spin_lock_init(&client->ctx_lock);
	INIT_LIST_HEAD(&client->ctx_list);

	client->clients = clients;

	ret = xa_alloc_cyclic(&clients->xarray, &client->id, client,
			      xa_limit_32b, &clients->next_id, GFP_KERNEL);
	if (ret)
		goto err_id;

	ret = __i915_drm_client_register(client, task);
	if (ret)
		goto err_register;

	return client;

err_register:
	xa_erase(&clients->xarray, client->id);
err_id:
	kfree(client);

	return ERR_PTR(ret);
}

void __i915_drm_client_free(struct kref *kref)
{
	struct i915_drm_client *client =
		container_of(kref, typeof(*client), kref);

	__i915_drm_client_unregister(client);
	xa_erase(&client->clients->xarray, client->id);
	kfree_rcu(client, rcu);
}

void i915_drm_client_close(struct i915_drm_client *client)
{
	GEM_BUG_ON(READ_ONCE(client->closed));
	WRITE_ONCE(client->closed, true);
	i915_drm_client_put(client);
}

struct client_update_free {
	struct rcu_head rcu;
	struct pid *pid;
	char *name;
};

static void __client_update_free(struct rcu_head *rcu)
{
	struct client_update_free *old = container_of(rcu, typeof(*old), rcu);

	put_pid(old->pid);
	kfree(old->name);
	kfree(old);
}

int
i915_drm_client_update(struct i915_drm_client *client,
		       struct task_struct *task)
{
	struct drm_i915_private *i915 =
		container_of(client->clients, typeof(*i915), clients);
	struct client_update_free *old;
	struct pid *pid;
	char *name;
	int ret;

	old = kmalloc(sizeof(*old), GFP_KERNEL);
	if (!old)
		return -ENOMEM;

	ret = mutex_lock_interruptible(&client->update_lock);
	if (ret)
		goto out_free;

	pid = get_task_pid(task, PIDTYPE_PID);
	if (!pid)
		goto out_pid;
	if (pid == rcu_access_pointer(client->pid))
		goto out_name;

	name = kstrdup(task->comm, GFP_KERNEL);
	if (!name) {
		drm_notice(&i915->drm,
			   "Failed to update client id=%u,name=%s,pid=%u! (%d)\n",
			   client->id, client->name, pid_nr(client->pid), ret);
		goto out_name;
	}

	init_rcu_head(&old->rcu);

	old->pid = rcu_replace_pointer(client->pid, pid, true);
	old->name = rcu_replace_pointer(client->name, name, true);

	mutex_unlock(&client->update_lock);

	call_rcu(&old->rcu, __client_update_free);

	return 0;

out_name:
	put_pid(pid);
out_pid:
	mutex_unlock(&client->update_lock);
out_free:
	kfree(old);

	return ret;
}
