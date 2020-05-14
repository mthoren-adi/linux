// SPDX-License-Identifier: GPL-2.0+
/**
 * The JESD204 framework - finite state machine logic
 *
 * Copyright (c) 2019 Analog Devices Inc.
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/of.h>

#include "jesd204-priv.h"

#define JESD204_LINKS_ALL	((unsigned int)-1)

extern struct list_head jesd204_topologies;

/**
 * struct jesd204_fsm_data - JESD204 device state change data
 * @jdev_top		top JESD204 for which this state change
 * @propagated_cb	callback to propagate to trigger state change
 * @inputs		true if this is running on the inputs
 */
struct jesd204_fsm_data {
	struct jesd204_dev_top		*jdev_top;
	jesd204_cb_priv		fsm_change_cb;
	bool				inputs;
};

typedef int (*jesd204_propagated_cb)(struct jesd204_dev *jdev,
				     struct jesd204_link_opaque *ol,
				     struct jesd204_dev_con_out *con,
				     struct jesd204_fsm_data *data);

/**
 * struct jesd204_fsm_table_entry - JESD204 link states table entry
 * @state		target JESD204 state
 * @op			callback ID associated with transitioning to @state
 * @last		marker for the last state in the transition series
 */
struct jesd204_fsm_table_entry {
	enum jesd204_dev_state	state;
	enum jesd204_dev_op	op;
	bool			last;
};

struct jesd204_fsm_table_entry_iter {
	const struct jesd204_fsm_table_entry	*table;
	unsigned int				link_idx;
};

#define _JESD204_STATE_OP(x, _last)	\
{					\
	.state = JESD204_STATE_##x,	\
	.op = JESD204_OP_##x,		\
	.last = _last			\
}
#define JESD204_STATE_OP(x)		_JESD204_STATE_OP(x, false)
#define JESD204_STATE_OP_LAST(x)	_JESD204_STATE_OP(x, true)

static int jesd204_fsm_table(struct jesd204_dev *jdev,
			     unsigned int link_idx,
			     enum jesd204_dev_state init_state,
			     const struct jesd204_fsm_table_entry *table);

/* States to transition to initialize a JESD204 link */
static const struct jesd204_fsm_table_entry jesd204_init_links_states[] = {
	JESD204_STATE_OP_LAST(LINK_INIT),
};

/* States to transition to start a JESD204 link */
static const struct jesd204_fsm_table_entry jesd204_start_links_states[] = {
	JESD204_STATE_OP(LINK_SUPPORTED),
	JESD204_STATE_OP(LINK_SETUP),
	JESD204_STATE_OP(CLOCKS_ENABLE),
	JESD204_STATE_OP(LINK_ENABLE),
	JESD204_STATE_OP_LAST(LINK_RUNNING),
};

/* States to transition when unregistering a device */
static const struct jesd204_fsm_table_entry jesd204_unreg_dev_states[] = {
	JESD204_STATE_OP(LINK_DISABLE),
	JESD204_STATE_OP(CLOCKS_DISABLE),
	JESD204_STATE_OP_LAST(LINK_UNINIT),
};

static bool jesd204_con_belongs_to_topology(struct jesd204_dev_con_out *con,
					    struct jesd204_dev_top *jdev_top)
{
	int i;

	if (jdev_top->topo_id != con->topo_id)
		return false;

	for (i = 0; i < jdev_top->num_links; i++) {
		if (con->link_id == jdev_top->link_ids[i])
			return true;
	}

	return false;
}

const char *jesd204_state_str(enum jesd204_dev_state state)
{
	switch (state) {
	case JESD204_STATE_ERROR:
		return "error";
	case JESD204_STATE_UNINIT:
		return "uninitialized";
	case JESD204_STATE_INITIALIZED:
		return "initialized";
	case JESD204_STATE_PROBED:
		return "probed";
	case JESD204_STATE_LINK_INIT:
		return "link_init";
	case JESD204_STATE_LINK_SUPPORTED:
		return "link_supported";
	case JESD204_STATE_LINK_SETUP:
		return "link_setup";
	case JESD204_STATE_CLOCKS_ENABLE:
		return "clocks_enable";
	case JESD204_STATE_CLOCKS_DISABLE:
		return "clocks_disable";
	case JESD204_STATE_LINK_ENABLE:
		return "link_enable";
	case JESD204_STATE_LINK_DISABLE:
		return "link_disable";
	case JESD204_STATE_LINK_RUNNING:
		return "link_running";
	case JESD204_STATE_LINK_UNINIT:
		return "link_uninit";
	case JESD204_STATE_DONT_CARE:
		return "dont_care";
	default:
		return "<unknown>";
	}
}

static int jesd204_dev_set_error(struct jesd204_link_opaque *jlink,
				 struct jesd204_dev_con_out *con,
				 int err)
{
	/* FIXME: should we exit here? */
	if (err == 0)
		return 0;

	if (con)
		con->error = err;

	jlink->error = err;

	return err;
}

static int jesd204_dev_propagate_cb_inputs(struct jesd204_dev *jdev,
					   struct jesd204_link_opaque *ol,
					   jesd204_propagated_cb propagated_cb,
					   struct jesd204_fsm_data *data)
{
	struct jesd204_dev_top *jdev_top = data->jdev_top;
	struct jesd204_dev_con_out *con = NULL;
	unsigned int i;
	int ret = 0;

	for (i = 0; i < jdev->inputs_count; i++) {
		con = jdev->inputs[i];

		if (!jesd204_con_belongs_to_topology(con, jdev_top))
			continue;

		ret = jesd204_dev_propagate_cb_inputs(con->owner, ol,
						      propagated_cb, data);
		if (ret)
			break;
		ret = propagated_cb(con->owner, ol, con, data);
		if (ret)
			break;
	}

	return jesd204_dev_set_error(ol, con, ret);
}

static int jesd204_dev_propagate_cb_outputs(struct jesd204_dev *jdev,
					    struct jesd204_link_opaque *ol,
					    jesd204_propagated_cb propagated_cb,
					    struct jesd204_fsm_data *data)
{
	struct jesd204_dev_top *jdev_top = data->jdev_top;
	struct jesd204_dev_con_out *con = NULL;
	struct jesd204_dev_list_entry *e;
	int ret = 0;

	list_for_each_entry(con, &jdev->outputs, entry) {
		list_for_each_entry(e, &con->dests, entry) {
			if (!jesd204_con_belongs_to_topology(con, jdev_top))
				continue;

			ret = propagated_cb(e->jdev, ol, con, data);
			if (ret)
				goto done;
			ret = jesd204_dev_propagate_cb_outputs(e->jdev, ol,
							       propagated_cb,
							       data);
			if (ret)
				goto done;
		}
	}

done:
	return jesd204_dev_set_error(ol, con, ret);
}

static inline int jesd204_dev_propagate_cb(struct jesd204_dev *jdev,
					   struct jesd204_link_opaque *ol,
					   jesd204_propagated_cb propagated_cb,
					   struct jesd204_fsm_data *data)
{
	int ret;

	data->inputs = true;
	ret = jesd204_dev_propagate_cb_inputs(jdev, ol, propagated_cb, data);
	if (ret)
		goto out;

	data->inputs = false;
	ret = jesd204_dev_propagate_cb_outputs(jdev, ol, propagated_cb, data);
	if (ret)
		goto out;

	ret = propagated_cb(jdev, ol, NULL, data);
out:
	return jesd204_dev_set_error(ol, NULL, ret);
}

static void __jesd204_link_fsm_change_cb(struct kref *ref)
{
	struct jesd204_link_opaque *ol;
	struct jesd204_dev *jdev;
	int ret;

	ol = container_of(ref, typeof(*ol), cb_ref);
	jdev = &ol->jdev_top->jdev;

	if (ol->error) {
		dev_err(jdev->parent, "jesd got error from topology %d\n",
			ol->error);
		ol->cur_state = JESD204_STATE_ERROR;
		goto out;
	}

	dev_info(jdev->parent, "JESD204 link[%u] transition %s -> %s\n",
		 ol->link_idx,
		 jesd204_state_str(ol->cur_state),
		 jesd204_state_str(ol->nxt_state));
	ol->cur_state = ol->nxt_state;

	if (ol->fsm_complete_cb) {
		ret = ol->fsm_complete_cb(jdev, ol, ol->cb_data);
		jesd204_dev_set_error(ol, NULL, ret);
		if (ret) {
			dev_err(jdev->parent,
				"error from completion cb %d, state %s\n",
				ret,
				jesd204_state_str(ol->cur_state));
			ol->cur_state = JESD204_STATE_ERROR;
			goto out;
		}
	}

out:
	/**
	 * Reset nxt_state ; so that other devices won't run another
	 * state change
	 */
	ol->nxt_state = JESD204_STATE_UNINIT;
	ol->cb_data = NULL;
}

static int jesd204_dev_validate_cur_state(struct jesd204_dev *jdev,
					  struct jesd204_link_opaque *ol,
					  struct jesd204_dev_con_out *c,
					  enum jesd204_dev_state state)
{
	if (state != ol->cur_state &&
	    state != JESD204_STATE_DONT_CARE) {
		dev_warn(jdev->parent,
			 "JESD204 link[%u] invalid current state: %s, exp: %s, nxt: %s\n",
			 ol->link_idx,
			 jesd204_state_str(ol->cur_state),
			 jesd204_state_str(state),
			 jesd204_state_str(ol->nxt_state));
		return jesd204_dev_set_error(ol, c, -EINVAL);
	}

	return 0;
}

static int jesd204_dev_update_con_state(struct jesd204_dev *jdev,
					struct jesd204_link_opaque *ol,
					struct jesd204_dev_con_out *c)
{
	int ret;

	if (!c || c->state == ol->nxt_state)
		return 0;

	if (ol->nxt_state == JESD204_STATE_UNINIT)
		return 0;

	kref_get(&ol->cb_ref);

	ret = jesd204_dev_validate_cur_state(jdev, ol, c, c->state);
	if (ret)
		return ret;

	c->state = ol->nxt_state;
	kref_put(&ol->cb_ref, __jesd204_link_fsm_change_cb);

	return 0;
}

static int jesd204_fsm_cb(struct jesd204_dev *jdev,
			  struct jesd204_link_opaque *ol,
			  struct jesd204_dev_con_out *con,
			  struct jesd204_fsm_data *s)
{
	int ret;

	kref_get(&ol->cb_ref);

	if (s->fsm_change_cb) {
		ret = s->fsm_change_cb(jdev, ol, con, ol->cb_data);
		if (ret < 0)
			return ret;
	} else {
		ret = JESD204_STATE_CHANGE_DONE;
	}

	if (ret == JESD204_STATE_CHANGE_DONE) {
		ret = jesd204_dev_update_con_state(jdev, ol, con);
		kref_put(&ol->cb_ref,  __jesd204_link_fsm_change_cb);
	} else {
		ret = 0;
	}

	return ret;
}

static int __jesd204_fsm_for_one_link(struct jesd204_dev *jdev,
				      struct jesd204_dev_top *jdev_top,
				      unsigned int link_idx,
				      enum jesd204_dev_state cur_state,
				      enum jesd204_dev_state nxt_state,
				      jesd204_cb_priv fsm_change_cb,
				      void *cb_data,
				      jesd204_cb_ol_priv fsm_complete_cb)
{
	struct jesd204_link_opaque *ol = &jdev_top->active_links[link_idx];
	struct jesd204_fsm_data data;
	int ret;

	ret = jesd204_dev_validate_cur_state(jdev, ol, NULL, cur_state);
	if (ret)
		return ret;

	kref_init(&ol->cb_ref);

	memset(&data, 0, sizeof(data));
	data.fsm_change_cb = fsm_change_cb;
	data.jdev_top = jdev_top;

	ol->fsm_complete_cb = fsm_complete_cb;
	ol->nxt_state = nxt_state;
	ol->cb_data = cb_data;
	if (cur_state == JESD204_STATE_DONT_CARE)
		ol->cur_state = JESD204_STATE_DONT_CARE;

	ret = jesd204_dev_propagate_cb(jdev, ol,
				       jesd204_fsm_cb,
				       &data);

	kref_put(&ol->cb_ref,
		 __jesd204_link_fsm_change_cb);

	return ret;
}

static int __jesd204_fsm(struct jesd204_dev *jdev,
			 struct jesd204_dev_top *jdev_top,
			 unsigned int link_idx,
			 enum jesd204_dev_state cur_state,
			 enum jesd204_dev_state nxt_state,
			 jesd204_cb_priv fsm_change_cb,
			 void *cb_data,
			 jesd204_cb_ol_priv fsm_complete_cb)
{
	int ret;

	if (link_idx != JESD204_LINKS_ALL)
		return __jesd204_fsm_for_one_link(jdev, jdev_top, link_idx,
						  cur_state, nxt_state,
						  fsm_change_cb, cb_data,
						  fsm_complete_cb);

	for (link_idx = 0; link_idx < jdev_top->num_links; link_idx++) {
		ret = __jesd204_fsm_for_one_link(jdev, jdev_top, link_idx,
						 cur_state, nxt_state,
						 fsm_change_cb, cb_data,
						 fsm_complete_cb);
		if (ret)
			return ret;
	}

	return 0;
}

static bool jesd204_dev_belongs_to_top_dev(struct jesd204_dev *jdev,
					   struct jesd204_dev_top *jdev_top)
{
	struct jesd204_dev_con_out *c;
	int i;

	list_for_each_entry(c, &jdev->outputs, entry) {
		if (jesd204_con_belongs_to_topology(c, jdev_top))
			return true;
	}

	for (i = 0; i < jdev->inputs_count; i++) {
		c = jdev->inputs[i];
		if (jesd204_con_belongs_to_topology(c, jdev_top))
			return true;
	}

	return false;
}

static int jesd204_fsm(struct jesd204_dev *jdev,
		       unsigned int link_idx,
		       enum jesd204_dev_state cur_state,
		       enum jesd204_dev_state nxt_state,
		       jesd204_cb_priv fsm_change_cb,
		       void *cb_data,
		       jesd204_cb_ol_priv fsm_complete_cb)
{
	struct list_head *jesd204_topologies = jesd204_topologies_get();
	struct jesd204_dev_top *jdev_top = jesd204_dev_top_dev(jdev);
	int ret;

	if (jdev_top)
		return __jesd204_fsm(jdev, jdev_top, link_idx,
				     cur_state, nxt_state, fsm_change_cb,
				     cb_data, fsm_complete_cb);

	list_for_each_entry(jdev_top, jesd204_topologies, entry) {
		if (!jesd204_dev_belongs_to_top_dev(jdev, jdev_top))
			continue;

		ret = __jesd204_fsm(jdev, jdev_top, link_idx,
				    cur_state, nxt_state, fsm_change_cb,
				    cb_data, fsm_complete_cb);
		if (ret)
			return ret;
	}

	return 0;
}

static int jesd204_dev_initialize_cb(struct jesd204_dev *jdev,
				     struct jesd204_link_opaque *ol,
				     struct jesd204_dev_con_out *con,
				     void *data)
{
	if (con && ol->link.link_id == con->link_id)
		con->jdev_top = data;

	return JESD204_STATE_CHANGE_DONE;
}

int jesd204_init_topology(struct jesd204_dev_top *jdev_top)
{
	if (!jdev_top)
		return -EINVAL;

	return jesd204_fsm(&jdev_top->jdev, JESD204_LINKS_ALL,
			   JESD204_STATE_UNINIT, JESD204_STATE_INITIALIZED,
			   jesd204_dev_initialize_cb, jdev_top, NULL);
}

static int jesd204_fsm_probed_cb(struct jesd204_dev *jdev,
				 struct jesd204_link_opaque *ol,
				 struct jesd204_dev_con_out *con,
				 void *data)
{
	if (!jdev->parent)
		return JESD204_STATE_CHANGE_DEFER;
	return JESD204_STATE_CHANGE_DONE;
}

static int jesd204_fsm_probe_done(struct jesd204_dev *jdev,
				  struct jesd204_link_opaque *ol,
				  void *data)
{
	int ret;

	ret = jesd204_fsm_init_links(jdev, JESD204_STATE_PROBED);
	if (ret)
		return ret;

	return jesd204_fsm_start_links(jdev, JESD204_STATE_LINK_INIT);
}

int jesd204_fsm_probe(struct jesd204_dev *jdev)
{
	return jesd204_fsm(jdev, JESD204_LINKS_ALL,
			   JESD204_STATE_INITIALIZED, JESD204_STATE_PROBED,
			   jesd204_fsm_probed_cb, NULL, jesd204_fsm_probe_done);
}

static int jesd204_fsm_table_entry_cb(struct jesd204_dev *jdev,
				      struct jesd204_link_opaque *ol,
				      struct jesd204_dev_con_out *con,
				      void *data)
{
	struct jesd204_fsm_table_entry_iter *it = data;
	jesd204_link_cb link_op;

	if (!jdev->link_ops)
		return JESD204_STATE_CHANGE_DONE;

	link_op = jdev->link_ops[it->table[0].op];
	if (!link_op)
		return JESD204_STATE_CHANGE_DONE;

	return link_op(jdev, ol->link_idx, &ol->link);
}

static int jesd204_fsm_table_entry_done(struct jesd204_dev *jdev,
					struct jesd204_link_opaque *ol,
					void *data)
{
	struct jesd204_fsm_table_entry_iter *it = data;
	const struct jesd204_fsm_table_entry *table = it->table;

	if (table[0].last)
		return 0;

	return jesd204_fsm_table(jdev, it->link_idx, table[0].state, &table[1]);
}

static int jesd204_fsm_table(struct jesd204_dev *jdev,
			     unsigned int link_idx,
			     enum jesd204_dev_state init_state,
			     const struct jesd204_fsm_table_entry *table)
{
	struct jesd204_fsm_table_entry_iter it;

	it.link_idx = link_idx;
	it.table = table;

	return jesd204_fsm(jdev, link_idx,
			   init_state, table[0].state,
			   jesd204_fsm_table_entry_cb,
			   &it,
			   jesd204_fsm_table_entry_done);
}

int jesd204_fsm_init_links(struct jesd204_dev *jdev,
			   enum jesd204_dev_state init_state)
{
	int ret;

	ret = jesd204_fsm_table(jdev, JESD204_LINKS_ALL,
				init_state, jesd204_init_links_states);
	if (ret)
		return ret;

	return jesd204_dev_init_link_data(jdev);
}

int jesd204_fsm_start_links(struct jesd204_dev *jdev,
			    enum jesd204_dev_state init_state)
{
	return jesd204_fsm_table(jdev, JESD204_LINKS_ALL,
				 init_state, jesd204_start_links_states);
}

void jesd204_fsm_unreg_device(struct jesd204_dev *jdev)
{
	jesd204_fsm_table(jdev, JESD204_LINKS_ALL,
			  JESD204_STATE_DONT_CARE, jesd204_unreg_dev_states);
}

int jesd204_fsm_link_change(struct jesd204_dev_top *jdev_top,
			    unsigned int link_idx)
{
	struct jesd204_link_opaque *oal, *osl;
	struct jesd204_link *al, *sl;
	int ret;

	if (link_idx >= jdev_top->num_links)
		return -EINVAL;

	oal = &jdev_top->active_links[link_idx];
	osl = &jdev_top->staged_links[link_idx];

	al = &oal->link;
	sl = &osl->link;

	/* If no links staged, there is nothing to do */
	if (memcmp(al, sl, sizeof(*al)) == 0)
		return 0;

	ret = jesd204_fsm_table(&jdev_top->jdev, link_idx,
				oal->cur_state,
				jesd204_unreg_dev_states);
	if (ret)
		return ret;

	if (!sl->enabled)
		goto save_link_settings;

	ret = jesd204_fsm_table(&jdev_top->jdev, link_idx,
				oal->cur_state,
				jesd204_start_links_states);
	if (ret)
		return ret;

save_link_settings:
	/* Save new active link settings */
	memcpy(al, sl, sizeof(*al));

	return 0;
}
