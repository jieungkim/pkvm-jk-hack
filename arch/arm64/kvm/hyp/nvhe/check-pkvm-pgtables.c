
/*
#include <asm/kvm_asm.h>

void record_hyp_mappings(phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base);
#define CHECK_QUIET false
#define CHECK_NOISY true
bool check_hyp_mappings(kvm_pte_t *pgd, bool noisy);
void dump_pgtable(struct kvm_pgtable pg);
void dump_kvm_nvhe_init_params(struct kvm_nvhe_init_params *params);
*/

// PS HACK

// experiment with C executable version of the main EL2 page-table
// spec established by pKVM initialisation, using C versions of the
// EL2 address translation definition, in a style that could easily be
// used by the pKVM devs.

// We might be able to check that something like this "semantics" of
// address translation is equivalent to the Armv8-A ASL definition
// (under a raft of system-state assumptions appropriate to pKVM)
// simply by using isla on the compiled binary and asking an SMT
// solver - after unfolding everything, there wouldn't be that many
// cases.

// And we might be able to prove in RefinedC / CN that the actual
// page-table setup, done by pKVM in setup.c recreate_hyp_mappings
// using hyp_create_mappings using kvm_pgtable_hyp_map, establishes
// this.

// How we design the refinement-type assertion language(s) to make it
// easy to express this kind of thing in a way that can easily be
// shown to correspond to this executable C version is an interesting
// question...

// Note that as written this checks a sample minimal fact about pKVM's
// own putative mapping at hyp_pgtable, not whatever is installed in
// TTBR0_EL2, so it's suitable for use _before_ the idmap tango, not
// necessarily after.
//
// Note that it reads pagetable contents just using the current
// mapping, whatever that is - one needs assumptions about that to
// make this assertion check meaningful.


#include <asm/kvm_pgtable.h>
//#include <asm/kvm_asm.h>
//#include <nvhe/memory.h>
#include <nvhe/mm.h>
#include <linux/bits.h>

#include <nvhe/early_alloc.h>


#include <asm/kvm_mmu.h>
#include <../debug-pl011.h>
#include <../check-debug-pl011.h>

// copy of linux sort library to make be linked in to nvhe.  likely there is a much better way to do this...
#include <nvhe/sort_hack.h>




void record_hyp_mappings(phys_addr_t phys, uint64_t size, uint64_t nr_cpus, unsigned long *per_cpu_base) {
}


bool check_hyp_mappings(kvm_pte_t *pgd, bool noisy) {
  return true;
}

void dump_pgtable(struct kvm_pgtable pg) {

}

/* **************************************** */
/* print key system register values */
void dump_kvm_nvhe_init_params(struct kvm_nvhe_init_params *params)
{
        hyp_putsxn("mair_el2    ", params->mair_el2     , 64); hyp_putc('\n');
        hyp_putsxn("tcr_el2     ", params->tcr_el2      , 64); hyp_putc('\n');
        hyp_putsxn("tpidr_el2   ", params->tpidr_el2    , 64); hyp_putc('\n');
        hyp_putsxn("stack_hyp_va", params->stack_hyp_va , 64); hyp_putc('\n');
        hyp_putsxn("pgd_pa      ", (unsigned long)params->pgd_pa       , 64); hyp_putc('\n');
        hyp_putsxn("hcr_el2     ", params->hcr_el2      , 64); hyp_putc('\n');
        hyp_putsxn("vttbr       ", params->vttbr        , 64); hyp_putc('\n');
        hyp_putsxn("vtcr        ", params->vtcr         , 64); hyp_putc('\n');
}
