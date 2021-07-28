// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <asm/kvm_hyp.h>
#include <nvhe/gfp.h>

u64 __hyp_vmemmap;

// JK:


// PS: the following are to get debug printing via the uart
#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>
#include <../check-debug-pl011.h>

/* ****************************************************************** */
/* PS: start encoding some of that into C. There's a lot of choice
   here, and we have to pay unfortunately much attention to making it
   feasible to compute; the following is a bit arbitrary, and not
   terribly nice - it avoids painful computation of the "partitions
   the pages" part, but is probably more algorithmic than we'd like,
   esp. in the check_page_groups_and_interpret loop
   structure. Although for refinement-type proof, we may want the
   invariants to be as far as possible about the concrete data, rather
   than about abstractions thereof.  So far the checking code below is
   computing but not using the abstraction.  Is the abstraction what
   we want to use for the external spec of this module?  (This seems a
   bit different to the pgtable case, where some elaboration of the
   abstraction is probably useful in specs of the recursive functions
   of the implementation) */


// RL: maybe we really want to maintain a forest of binary trees?

/* types of abstraction */

struct page_group {
  phys_addr_t start;
  unsigned int order;
  bool free;
};

#define MAX_PAGE_GROUPS 0x10000  /* horrible hack */

struct page_groups {
  struct page_group page_group[MAX_PAGE_GROUPS];
  u64 count;
};

struct page_groups page_groups_a;


static bool during_initialization;

// USED pages should be continuously assigned
// Check whether phys is in between the used pages
bool in_used_pages(phys_addr_t phys, struct hyp_pool *pool)
{
  return phys < pool->range_start + PAGE_SIZE*pool->used_pages;
}

/* pretty-printing */

void put_page_group(struct page_group *pg, struct hyp_pool *pool) {
  hyp_putsp("Page group info - ");
  hyp_putsxn("page group start ", pg->start,64);
  hyp_putsxn("/ end ",pg->start + PAGE_SIZE*(1ul << pg->order),64);
  hyp_putsxn("/ order ",pg->order,32);
  hyp_putsp("/ used_pages ");
  hyp_putbool(in_used_pages(pg->start,pool));
  hyp_putsp("/ free ");
  hyp_putbool(pg->free);
  hyp_putsp("\n");
}

/**
 * list_entry - get the struct for this entry
 * @ptr:        the &struct list_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 */
/* #define list_entry(ptr, type, member) container_of(ptr, type, member) */

void put_free_list(struct list_head *head)
{
  struct list_head *pos;
  list_for_each(pos,head) {
    struct hyp_page *p = hyp_virt_to_page(pos);
    hyp_putsxn("", (u64)hyp_page_to_phys(p), 64);
  }
}

// Prints all lists (all orders
void put_free_lists(struct hyp_pool *pool)
{
  u64 i;
  for (i=0; i<pool->max_order; i++) {
    hyp_putsxn("order",i,64);
    put_free_list(&pool->free_area[i]);
    hyp_putc('\n');
  }
}

bool check_free_list(struct list_head *head, unsigned int order, struct hyp_pool *pool)
{
  bool ret;
  struct list_head *pos;
  struct hyp_page *p; 
  phys_addr_t phys;
  ret = true;

  // use the macro
  list_for_each(pos, head) { //for (pos = head->next; pos != (head); pos = pos->next) {
    p = hyp_virt_to_page(pos);
    phys = hyp_page_to_phys(p);

    // If phys are already used, or out of range that are marked with pool
    // range, error.
    if (phys < pool->range_start + PAGE_SIZE*pool->used_pages ||
        phys >= pool->range_end) {
      ret = false;
      hyp_putsxn("phys",(u64)phys,64);
      hyp_putc('\n');
      hyp_putbool(phys < pool->range_start + PAGE_SIZE*pool->used_pages);
      hyp_putc('\n');
      hyp_putbool(phys >= pool->range_end);
      hyp_putc('\n');
      check_assert_fail("free list entry not in pool unused_page range");
    }   
      // hyp_putsxn("phys",(u64)phys,64);
      // hyp_putc('\n');
      // hyp_putbool(phys < pool->range_start + PAGE_SIZE*pool->used_pages);
      // hyp_putc('\n');
      // hyp_putbool(phys >= pool->range_end);
      // hyp_putc('\n')
      //  
      // maybe this should check p is the address of a hyp_page node member,
      // not just go straight to hyp_page_to_phys's notion of phys
      //  
      // If order is not equal, then return false
      if (p->order != order) {
        ret=false;
        hyp_putsxn("phys",(u64)phys,64);
        check_assert_fail("free list entry (free page) has wrong order");
      }   
    }   
    return ret;
}

/* well-formed free lists of pool */
bool check_free_lists(struct hyp_pool *pool)
{
  u64 i;
  bool ret;
  ret = true;
  for (i=0; i<pool->max_order; i++) {
    hyp_putsxn("start to check free lists with the order of ",(u64)i, 64);
    hyp_putc('\n');
    ret = ret &&
        check_free_list(&pool->free_area[i], i, pool);
  }
  return ret;
}

/* list auxiliary: check whether @node is an element of @head (curiously not already in linux/include/list.h) */
bool list_contains(struct list_head *node, struct list_head *head)
{ 
  struct list_head *pos;
  list_for_each(pos, head) { //for (pos = head->next; pos != (head); pos = pos->next) 
    if (pos==node)
      return true;
  }
  return false;
}

/* add page_group to abstraction */
void add_page_group(struct page_groups *pgs, phys_addr_t phys, unsigned int order, bool free, struct hyp_pool *pool)
{
  struct page_group *pg;

  // count will first start from 0
  pg = &pgs->page_group[pgs->count];
  if (pgs->count >= MAX_PAGE_GROUPS) {
    check_assert_fail("overran MAX_PAGE_GROUPS"); 
    return; 
  }

  pg->start = phys;
  pg->order = order;
  pg->free = free;

  // print out the page group that is added at this moment
  put_page_group(pg, pool);
  // add page groups
  pgs->count++;
}


static struct hyp_page *find_free_buddy(struct hyp_pool *pool,
                                             struct hyp_page *p, 
                                             unsigned short order)
{

        phys_addr_t addr = hyp_page_to_phys(p);
        struct hyp_page *buddy = hyp_phys_to_page(addr);

        addr ^= (PAGE_SIZE << order);

        /*
         * Don't return a page outside the pool range -- it belongs to
         * something else and may not be mapped in hyp_vmemmap.
         */
        if (addr < pool->range_start || addr >= pool->range_end)
                return NULL;

        if (!buddy || buddy->order != order || buddy->refcount)
                return NULL;
        return buddy;
}


/* well-formed page_group start page */
bool check_page_group_start(phys_addr_t phys, struct hyp_page *p, struct hyp_pool *pool)
{
  bool ret;
  ret = true;

  // order has to be specified
  if (p->order == HYP_NO_ORDER) {
    ret=false;
    hyp_putsxn("phys",(u64)phys,64);
    check_assert_fail("found HYP_NO_ORDER at next start page");
  }

  // order should be less than max_order
  if (p->order >= pool->max_order) {
    ret=false;
    hyp_putsxn("phys",(u64)phys,64);
    check_assert_fail("found over-large order in start page");
  }

  // page is unaligned
  if ((phys & GENMASK(p->order + PAGE_SHIFT - 1, 0)) != 0) {
    ret=false;
    hyp_putsxn("phys",(u64)phys,64);
    check_assert_fail("found unaligned page group in start page");
  }

  // page should be inside the end
  if (phys + PAGE_SIZE*(1ul << p->order) > pool->range_end) {
    ret=false;
    hyp_putsxn("phys",(u64)phys,64);
    check_assert_fail("body runs over range_end");
  }

  // Page should not be used at all
  if (!during_initialization) {
    return ret;
  }

  if ((p->refcount != 0) || in_used_pages(phys,pool)) {
    ret=false;
    hyp_putsxn("phys",(u64)phys,64);
    check_assert_fail("found non-empty list in refcount!=0 or used_pages start page");
  }
  if (find_free_buddy(pool, p, p->order) != NULL) {
    ret=false;
    hyp_putsxn("phys",(u64)phys,64);
    check_assert_fail("found free buddy");
  }
  return ret;
}

/* well-formed page_group body page */
bool check_page_group_body(struct hyp_page *pbody, struct hyp_pool *pool)
{
  bool ret;
  ret= true;

  // the order has not to be specified
  if (pbody->order != HYP_NO_ORDER) {
    ret=false; check_assert_fail("found non-HYP_NO_ORDER in body");
  }
  // refcount needs to be zero - this page should not be allocated via
  // anyone
  if (pbody->refcount !=0) {
    ret=false; check_assert_fail("found non-zero refcount in body");
  }
  return ret;
}



/* well-formed page_group */
bool check_page_group(phys_addr_t phys, struct hyp_page *p, struct hyp_pool *pool)
{ 
  bool ret;
  struct hyp_page *pbody;
  
  // check page group start with 
  // phys: each page's start address
  // p: translate page address to hyp_page structure 
  // pool: pool (to check the existence?
  ret = check_page_group_start(phys, p, pool);
  
  // For each address in the hyp_page, check whether the
  // page is in the pool
  for (pbody=p+1; pbody < p+(1ul << (p->order)); pbody++) {
    ret = ret && check_page_group_body(pbody, pool);
  }
  return ret;
}

/* check all page groups and compute abstraction */
bool check_page_groups_and_interpret(struct page_groups* pgs, struct hyp_pool *pool)
{
  phys_addr_t phys;
  struct hyp_page *p;

  bool temp_ret;
  bool ret;
  ret = true;
  temp_ret = true;
  pgs->count = 0;
  // from start to the end,
  phys = pool->range_start;
  while (phys < pool->range_end) {
    p = hyp_phys_to_page(phys);
    // check each page 
    temp_ret = check_page_group(phys, p, pool);
    ret = ret && temp_ret;
    // add page group  
    // pgs: page groups - global variable 
    // phys: physical address of the page that will be added at this
    // moment
    // p->refcount == 0 : free or not 
    // pool: to print out values (not for assign values in
    // page_groups
    add_page_group(pgs, phys, p->order, (p->refcount == 0), pool);
    phys += PAGE_SIZE*(1ul << p->order);
  }
  return ret;
}

bool check_alloc_invariant(struct hyp_pool *pool) {
  bool ret;
  bool interpret_ret = true;
  bool check_free_lists_ret = true;
  ret = true;
  // Check whether the pool can be interpreted correctly with 
  // page groups
  interpret_ret = check_page_groups_and_interpret(&page_groups_a, pool);
  // check whether pages in the pool is free.
  check_free_lists_ret = check_free_lists(pool);
  
  ret = ret && interpret_ret && check_free_lists_ret;
  // print free lists - This one does not have any interesting invariant
  // checks, but it prints out free lists on the console
  put_free_lists(pool);
  hyp_putsp("Result of check page gruops and interpret: ");
  hyp_putbool(interpret_ret);
  hyp_putc('\n');
  hyp_putsp("Result of check free lists ret: ");
  hyp_putbool(check_free_lists_ret);
  hyp_putc('\n');
  if (!ret)
    hyp_putsp("check_alloc_invariant failed\n");
  else
    hyp_putsp("check_alloc_invariant succeed\n");
  
  return ret;
}

/*
 * Index the hyp_vmemmap to find a potential buddy page, but make no assumption
 * about its current state.
 *
 * Example buddy-tree for a 4-pages physically contiguous pool:
 *
 *                 o : Page 3
 *                /
 *               o-o : Page 2
 *              /
 *             /   o : Page 1
 *            /   /
 *           o---o-o : Page 0
 *    Order  2   1 0
 *
 * Example of requests on this pool:
 *   __find_buddy_nocheck(pool, page 0, order 0) => page 1
 *   __find_buddy_nocheck(pool, page 0, order 1) => page 2
 *   __find_buddy_nocheck(pool, page 1, order 0) => page 0
 *   __find_buddy_nocheck(pool, page 2, order 0) => page 3
 */

/* PS: given the address p of a hyp_page in the vmemmap, and an order,
   return the address of the hyp_page of its buddy (the adjacent page
   group, either before or after) if its start page is within the pool range,
   otherwise return NULL */
/* PS: this is a pure-ish function: no non-local writes */
/* PS: looking at this range_end check: it only checks the base
   address of the buddy page group, not the end address. The range
   that the pool is initialised with is a nice power of two and
   suitably aligned, which is not the case in general. But the
   __hyp_attach_page also checks that the order of the buddy is the
   same as the order of the page its considering, which implies that
   all of the buddy must have been allocated sometime*/
/* PS: for the range_start check, should that really be range_start+PAGE_SIZE*used_pages?
   why is it ok as-is?  Because __hyp_attach_page also checks the buddy is in a free list, 
   and the used_pages never are */
static struct hyp_page *__find_buddy_nocheck(struct hyp_pool *pool,
					     struct hyp_page *p,
					     unsigned short order)
{
	phys_addr_t addr = hyp_page_to_phys(p);

	addr ^= (PAGE_SIZE << order);

	/*
	 * Don't return a page outside the pool range -- it belongs to
	 * something else and may not be mapped in hyp_vmemmap.
	 */
	if (addr < pool->range_start || addr >= pool->range_end)
		return NULL;

	return hyp_phys_to_page(addr);
}

/* Find a buddy page currently available for allocation */
static struct hyp_page *__find_buddy_avail(struct hyp_pool *pool,
					   struct hyp_page *p,
					   unsigned short order)
{
	struct hyp_page *buddy = __find_buddy_nocheck(pool, p, order);

	if (!buddy || buddy->order != order || buddy->refcount)
		return NULL;

	return buddy;

}

/*
 * Pages that are available for allocation are tracked in free-lists, so we use
 * the pages themselves to store the list nodes to avoid wasting space. As the
 * allocator always returns zeroed pages (which are zeroed on the hyp_put_page()
 * path to optimize allocation speed), we also need to clean-up the list node in
 * each page when we take it out of the list.
 */
static inline void page_remove_from_list(struct hyp_page *p)
{
	struct list_head *node = hyp_page_to_virt(p);

	__list_del_entry(node);
	memset(node, 0, sizeof(*node));
}

static inline void page_add_to_list(struct hyp_page *p, struct list_head *head)
{
	struct list_head *node = hyp_page_to_virt(p);

	INIT_LIST_HEAD(node);
	list_add_tail(node, head);
}

static inline struct hyp_page *node_to_page(struct list_head *node)
{
	return hyp_virt_to_page(node);
}

/* PS: given a hyp_page p in the vmemmap, transfer that page group (at the order in that hyp_page) back to the allocator, coalescing buddys as much as possible */
/* PS: note that the buddy->order != order check ensures that the buddy page-group is the same order as the one we're trying to coalesce with it, and also ensures, if buddy->order==order, that all of the buddy must have been allocated sometime, and so be inside range_start..range_end */
/* PS: can __hyp_attach_page mistakenly coalesce with the last unused_page?  No, because the used_pages have empty free lists */
static void __hyp_attach_page(struct hyp_pool *pool,
			      struct hyp_page *p)
{
	unsigned short order = p->order;
	struct hyp_page *buddy;

	memset(hyp_page_to_virt(p), 0, PAGE_SIZE << p->order);

	/*
	 * Only the first struct hyp_page of a high-order page (otherwise known
	 * as the 'head') should have p->order set. The non-head pages should
	 * have p->order = HYP_NO_ORDER. Here @p may no longer be the head
	 * after coallescing, so make sure to mark it HYP_NO_ORDER proactively.
	 */
	p->order = HYP_NO_ORDER;
	for (; (order + 1) < pool->max_order; order++) {
		buddy = __find_buddy_avail(pool, p, order);
		if (!buddy)
			break;

		/* Take the buddy out of its list, and coallesce with @p */
		page_remove_from_list(buddy);
		buddy->order = HYP_NO_ORDER;
		p = min(p, buddy);
	}

	/* Mark the new head, and insert it */
	p->order = order;
	page_add_to_list(p, &pool->free_area[order]);
}

// PS: precondition: p is a free (probably non-used_page) page-group of order at least order
/* Extract a page from the buddy tree, at a specific order */
// RL: isn't the first check dead code?
static struct hyp_page *__hyp_extract_page(struct hyp_pool *pool,
					   struct hyp_page *p,
					   unsigned short order)
{
	struct hyp_page *buddy;

	page_remove_from_list(p);
	while (p->order > order) {
		/*
		 * The buddy of order n - 1 currently has HYP_NO_ORDER as it
		 * is covered by a higher-level page (whose head is @p). Use
		 * __find_buddy_nocheck() to find it and inject it in the
		 * free_list[n - 1], effectively splitting @p in half.
		 */
		p->order--;
		buddy = __find_buddy_nocheck(pool, p, p->order);
		buddy->order = p->order;
		page_add_to_list(buddy, &pool->free_area[buddy->order]);
	}

	return p;
}

static inline void hyp_page_ref_inc(struct hyp_page *p)
{
	BUG_ON(p->refcount == USHRT_MAX);
	p->refcount++;
}

static inline int hyp_page_ref_dec_and_test(struct hyp_page *p)
{
	p->refcount--;
	return (p->refcount == 0);
}

static inline void hyp_set_page_refcounted(struct hyp_page *p)
{
	BUG_ON(p->refcount);
	p->refcount = 1;
}

static void __hyp_put_page(struct hyp_pool *pool, struct hyp_page *p)
{
	if (hyp_page_ref_dec_and_test(p))
		__hyp_attach_page(pool, p);
}

/*
 * Changes to the buddy tree and page refcounts must be done with the hyp_pool
 * lock held. If a refcount change requires an update to the buddy tree (e.g.
 * hyp_put_page()), both operations must be done within the same critical
 * section to guarantee transient states (e.g. a page with null refcount but
 * not yet attached to a free list) can't be observed by well-behaved readers.
 */
// PS: hand a reference-count of a page-group back to the allocator
// PS: ...actually transferring ownership if it's the last reference-count
// PS: precondition: the refcount for the page at hyp_virt addr is non-zero
// PS: decrement it
// PS: if the recount becomes zero, __hyp_attach_page the page group
// PS: all protected by the pool lock
// PS: some standard seplogic idiom for ref-counted ownership?
void hyp_put_page(struct hyp_pool *pool, void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);

	hyp_spin_lock(&pool->lock);
	__hyp_put_page(pool, p);
	hyp_spin_unlock(&pool->lock);
}

// PS: just bump the refcount for the page at hyp_virt addr
// PS: protected by the pool lock
// PS: precondition: this page group must be currently handed out (and not in used_pages)
void hyp_get_page(struct hyp_pool *pool, void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);

	hyp_spin_lock(&pool->lock);
	hyp_page_ref_inc(p);
	hyp_spin_unlock(&pool->lock);
}

// PS: ask for a page-group at some order, either zero'd or not depending on gfp_t mask; return the address of the vmemmap hyp_page (cast to void*) or NULL if it failed.
void *hyp_alloc_pages(struct hyp_pool *pool, unsigned short order)
{
	unsigned short i = order;
	struct hyp_page *p;

	hyp_spin_lock(&pool->lock);

	/* Look for a high-enough-order page */
	while (i < pool->max_order && list_empty(&pool->free_area[i]))
		i++;
	if (i >= pool->max_order) {
		hyp_spin_unlock(&pool->lock);
		return NULL;
	}

	/* Extract it from the tree at the right order */
	p = node_to_page(pool->free_area[i].next);
	p = __hyp_extract_page(pool, p, order);

	hyp_set_page_refcounted(p);
	hyp_spin_unlock(&pool->lock);

       // PS: add check.  later we may need to make these sample, not be re-run on every call
       hyp_putsxn("__hyp_alloc_pages order",order,32);
       hyp_putsxn(" returned p",(u64)p,64);
       check_alloc_invariant(pool);

	return hyp_page_to_virt(p);
}

// PS: initialise the buddy allocator into `pool`, giving it memory phys..phys+nr_pages<<PAGE_SHIFT, initialise all the corresponding vmemmap `struct hyp_page`s, and attach all of that after phys+used_pages<<PAGE_SHIFT to the free lists (which will presumably combine them as much as it can - is __hyp_attach_page commutative?)
// PS: precondition: phys is page-aligned (NB not highest-order aligned)
// PS: precondition: at the C semantics level, the "vmemmap is mapped" precondition is just ownership of the vmemmap array - but at a specific address that makes the arithmetic work
int hyp_pool_init(struct hyp_pool *pool, u64 pfn, unsigned int nr_pages,
                  // JK HACK : the following line is replaced to add 
                  // used_pages as an argument
                  // used_pages as an argument
                  // unsigned int reserved_pages)
                  unsigned int reserved_pages, unsigned used_pages)
// int hyp_pool_init(struct hyp_pool *pool, u64 pfn, unsigned int nr_pages,
// igned int reserved_pages)
{
	phys_addr_t phys = hyp_pfn_to_phys(pfn);
	struct hyp_page *p;
	int i;

       // PS: add:
       hyp_putsxn("hyp_pool_init phys",phys,64);
       hyp_putsp("\n");
       hyp_putsxn("phys - end",phys + (nr_pages << PAGE_SHIFT),64);
       hyp_putsp("\n");
       hyp_putsxn("nr_pages",nr_pages,32);
       hyp_putsp("\n");
       hyp_putsxn("used_pages",used_pages,32);
       hyp_putsp("\n");
       hyp_putsxn("reserved_pages",reserved_pages,32);
       hyp_putsp("\n");
       hyp_putsxn("PAGE_SHIFT", PAGE_SHIFT, 32); 
       hyp_putsp("\n");
       hyp_putsxn("get_order result", get_order(nr_pages << PAGE_SHIFT), 32);      
       hyp_putsp("\n");

	hyp_spin_lock_init(&pool->lock);
	pool->max_order = min(MAX_ORDER, get_order(nr_pages << PAGE_SHIFT));
	for (i = 0; i < pool->max_order; i++)
		INIT_LIST_HEAD(&pool->free_area[i]);
	pool->range_start = phys;
	pool->range_end = phys + (nr_pages << PAGE_SHIFT);

       // PS: add this to help state the invariant:
       pool->used_pages = used_pages;

       /* Init the vmemmap portion */
       // JK: Get the address 
	p = hyp_phys_to_page(phys);
       // PS: zero all the `struct hyp_page`s in the vmemmap that correspond to the pages given to the allocator
        // PS: and for each of them, record that it belongs to this pool, and initialise its `struct list_head node` to an empty list (pointing to itself)

	for (i = 0; i < nr_pages; i++) {
		p[i].order = 0;
		hyp_set_page_refcounted(&p[i]);
	}

	/* Attach the unused pages to the buddy tree */
	for (i = reserved_pages; i < nr_pages; i++)
		__hyp_put_page(pool, &p[i]);


        // PS : add invariant check
        during_initialization = true;
        check_alloc_invariant(pool);
        during_initialization = false;

	return 0;
}
