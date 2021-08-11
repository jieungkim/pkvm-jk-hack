// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <asm/kvm_pgtable.h>

#include <nvhe/early_alloc.h>
#include <nvhe/memory.h>

// JK HACK
#include <../debug-pl011.h>
#include <../check-debug-pl011.h>

struct kvm_pgtable_mm_ops hyp_early_alloc_mm_ops;
s64 __ro_after_init hyp_physvirt_offset;

static unsigned long base;
static unsigned long end;
static unsigned long cur;

// PS HACK TO EXPOSE cur
unsigned long hyp_early_alloc_cur(void)
{
  return cur;
}

// JK HACK: simply added additional invariants in it

static bool during_initialization;

void check_early_alloc_invariant(unsigned int nr_pages) {


  bool ret = true;
  if (end <= cur) {
    ret = false;
  }

  if (base >= end) {
    ret = false;
  }

  if (base > cur) {
    ret = false;
  }

  if (!during_initialization) {
    if (end - cur < (nr_pages << PAGE_SHIFT)) {
      ret = false;
    }
  }

  if (ret) {
    hyp_putsp("early_alloc_invariant check succeed\n");
  } else {
    hyp_putsp("early_alloc_invariant check failed\n");
  }
}
// JK HACK: end of invariants

unsigned long hyp_early_alloc_nr_used_pages(void)
{
	return (cur - base) >> PAGE_SHIFT;
}

void *hyp_early_alloc_contig(unsigned int nr_pages)
{
	unsigned long size = (nr_pages << PAGE_SHIFT);
	void *ret = (void *)cur;

	if (!nr_pages)
		return NULL;

	if (end - cur < size)
		return NULL;

	cur += size;
	memset(ret, 0, size);

	return ret;
}

void *hyp_early_alloc_page(void *arg)
{
        check_early_alloc_invariant(1);
	return hyp_early_alloc_contig(1);
}

void hyp_early_alloc_init(void *virt, unsigned long size)
{
	base = cur = (unsigned long)virt;
	end = base + size;

	hyp_early_alloc_mm_ops.zalloc_page = hyp_early_alloc_page;
	hyp_early_alloc_mm_ops.phys_to_virt = hyp_phys_to_virt;
	hyp_early_alloc_mm_ops.virt_to_phys = hyp_virt_to_phys;

        during_initialization = true;
        check_early_alloc_invariant(0);
        during_initialization = false;
}
