
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

/**********************************************
 * Address translation 
**********************************************/

/*************************************************************************
 * Page table entry kind 
 *************************************************************************/

// the logical entry kinds
typedef enum entry_kind {
  EK_INVALID,
  EK_BLOCK,
  EK_TABLE,
  EK_PAGE_DESCRIPTOR,
  EK_BLOCK_NOT_PERMITTED,
  EK_RESERVED,
  EK_DUMMY
} entry_kind_type;

// the entry kind bit representations
#define ENTRY_INVALID_0 0
#define ENTRY_INVALID_2 2
#define ENTRY_BLOCK 1
#define ENTRY_RESERVED 1
#define ENTRY_PAGE_DESCRIPTOR 3
#define ENTRY_TABLE 3

enum entry_kind entry_kind(unsigned long long pte, unsigned char level)
{
  switch(level) {
  case 0:
  case 1:
  case 2:
    {
      switch (pte & GENMASK(1,0)) {
      case ENTRY_INVALID_0:
      case ENTRY_INVALID_2:
	return EK_INVALID;
      case ENTRY_BLOCK:
	switch (level) {
	case 0:
	  return EK_BLOCK_NOT_PERMITTED;
	case 1:
        case 2:
	  return EK_BLOCK;
	}
      case ENTRY_TABLE:
	return EK_TABLE;
      default:
	// just to tell the compiler that the cases are exhaustive
	return EK_DUMMY;
      }
    }
  case 3:
    switch (pte & GENMASK(1,0)) {
    case ENTRY_INVALID_0:
    case ENTRY_INVALID_2:
      return EK_INVALID;
    case ENTRY_RESERVED:
      return EK_RESERVED;
    case ENTRY_PAGE_DESCRIPTOR:
      return EK_PAGE_DESCRIPTOR;
    }

  default:
    // just to tell the compiler that the cases are exhaustive
    return EK_DUMMY;
  }

  return EK_DUMMY;
}


/*************************************************************************
 * Page table walk related data structures
 *************************************************************************/

// Page table walk

enum Fault {
  Fault_None,
  Fault_AccessFlag,
  Fault_Alignment,
  Fault_Background,
  Fault_Domain,
  Fault_Permission,
  Fault_Translation,
  Fault_AddressSize,
  Fault_SyncExternal,
  Fault_SyncExternalOnWalk,
  Fault_SyncParity,
  Fault_SyncParityOnWalk,
  Fault_AsyncParity,
  Fault_AsyncExternal,
  Fault_Debug,
  Fault_TLBConflict,
  Fault_BranchTarget,
  Fault_HWUpdateAccessFlag,
  Fault_Lockdown,
  Fault_Exclusive,
  Fault_ICacheMaint
};

/* [XXX(JK) - I commented out the following part because 
struct
[[rc::refined_by("statuscode : Z")]]
[[rc::ptr_type("fault_record : ...")]]
FaultRecord {
  [[rc::field("statuscode @ int<u32>")]]
  enum Fault statuscode; // Fault Status
  //  AccType acctype; // Type of access that faulted
  //  FullAddress ipaddress; // Intermediate physical address
  //  boolean s2fs1walk; // Is on a Stage 1 page table walk
  //  boolean write; // TRUE for a write, FALSE for a read
  //  integer level; // For translation, access flag and permission faults
  //  bit extflag; // IMPLEMENTATION DEFINED syndrome for external aborts
  //  boolean secondstage; // Is a Stage 2 abort
  //  bits(4) domain; // Domain number, AArch32 only
  //  bits(2) errortype; // [Armv8.2 RAS] AArch32 AET or AArch64 SET
  //  bits(4) debugmoe; // Debug method of entry, from AArch32 only
};

struct 
FullAddress {
  unsigned long long address; // bits(52) address;
  // Can we annotate it with 1
  int NS; // bit NS; // '0' = Secure, '1' = Non-secure
};

struct 
AddressDescriptor {
  struct FaultRecord fault; // fault.statuscode indicates whether the address is valid
  //  MemoryAttributes memattrs;
  struct FullAddress paddress;
  unsigned long long vaddress; // bits(64) vaddress;
};

//struct Permissions {
// bits(3) ap; // Access permission bits
// bit xn; // Execute-never bit
// bit xxn; // [Armv8.2] Extended execute-never bit for stage 2
// bit pxn // Privileged execute-never bit
//}

struct TLBRecord {
 	//  Permissions        perms;
	//  bit 	             nG;	   // '0' = Global, '1' = not Global
	//  bits(4)	     domain;	   // AArch32 only
	//  bit		     GP;	   // Guarded Page
	//  boolean	     contiguous;   // Contiguous bit from page table
	//  integer	     level;	   // AArch32 Short-descriptor format: Indicates Section/Page
	//  integer	     blocksize;    // Describes size of memory translated in KBytes
	//  DescriptorUpdate   descupdate;   // [Armv8.1] Context for h/w update of table descriptor
	//  bit		     CnP;	   // [Armv8.2] TLB entry can be shared between different PEs
	struct AddressDescriptor  addrdesc;
};
*/ 

struct
TLBRecord {
  // flattend AddressDescriptor
  // - flattened FaultRecord (statuscode)
  enum Fault statuscode; 
  // - flattend FullAddress (address, NS)
  unsigned long long address;
  unsigned int NS; // bit NS; // '0' = secure, '1' = non-secure
  unsigned long long vaddress;
};

#define TLB_REC 0
#define INTERMEDIATE_ADDR 1

struct
LEVEL012_result {
  unsigned int decision; 

  unsigned long long intermediate_address;

  enum Fault statuscode; 
  unsigned long long address;
  unsigned int NS; // bit NS; // '0' = secure, '1' = non-secure
  unsigned long long vaddress;
};

struct TLBRecord mkFault(unsigned long long vaddress) {
  struct TLBRecord result;
  result.statuscode = Fault_Translation;
  result.address = 0;
  result.NS = 0;
  result.vaddress = vaddress;

  return result;
}

struct TLBRecord mkTranslation(unsigned long long vaddress, unsigned long long pa) {
  struct TLBRecord result;
  result.statuscode = Fault_None; 
  result.address = pa;
  result.NS = 1; 
  result.vaddress = vaddress;
  
  return result;
}


struct TLBRecord mkTLBRecord(enum Fault stat, unsigned long long pa,
			     unsigned int ns, unsigned long long vaddress) {
  struct TLBRecord result;
  result.statuscode = stat; 
  result.address = pa;
  result.NS = ns; 
  result.vaddress = vaddress;
  
  return result;
}

/* [XXX(JK) - this one is not working with the current RefinedC. Missing this
 * feature is already reported.
struct TLBRecord mkFault_error(unsigned long long vaddress) {
  struct TLBRecord r = 
    { .addrdesc = { .fault = { .statuscode=Fault_Translation },
      .paddress =  { .address=0, .NS=0 }, .vaddress = vaddress } };
  // massively oversimplified
  return r;
} 

struct TLBRecord mkTranslation(uint64_t vaddress, uint64_t pa) {
  struct TLBRecord r =
    { .addrdesc = { .fault = { .statuscode=Fault_None }, 
      .paddress =  { .address=pa, .NS=1 }, .vaddress = vaddress } };
  // massively oversimplified
  return r;
}
*/

struct LEVEL012_result mkFaultLevel012 (unsigned long long vaddress) {
  struct LEVEL012_result result;
  result.decision = TLB_REC;
  result.intermediate_address = 0;

  result.statuscode = Fault_Translation;
  result.address = 0;
  result.NS = 0;
  result.vaddress = vaddress;

  return result;
}

struct LEVEL012_result mkTranslationLevel012 (unsigned long long vaddress,
					      unsigned long long pa) {
  struct LEVEL012_result result;
  result.decision = TLB_REC;
  result.intermediate_address = 0;

  result.statuscode = Fault_None;
  result.address = pa;
  result.NS = 1;
  result.vaddress = vaddress;

  return result;
}

struct LEVEL012_result mkIntermediateLevel012 (unsigned long long intermediate) {
  struct LEVEL012_result result;
  result.decision = INTERMEDIATE_ADDR;  
  result.intermediate_address = intermediate;

  result.statuscode = Fault_None;
  result.address = 0;
  result.NS = 0;
  result.vaddress = 0;

  return result;
}

struct TLBRecord extractTLBRecord(struct LEVEL012_result res) {
  return mkTLBRecord(res.statuscode, res.address, res.NS, res.vaddress);
}

/*************************************************************************
 * Page table walk functions
 *************************************************************************/

// aarch64/translation/walk/AArch64.TranslationTableWalk
// TLBRecord AArch64.TranslationTableWalk(bits(52) ipaddress, boolean s1_nonsecure, bits(64) vaddress, AccType acctype, boolean iswrite, boolean secondstage, boolean s2fs1walk, integer size)

// There's a lot of detailed code here, but most relates to options
// that I think are irrelevant for us. The actual walk is the repeat
// loop on p7729-7730.  For now, I'll try for something clean that
// handles only the basic VA->PA part, ignoring attributes etc., not
// to follow the ASL closely.

// I've done this recursively, but we might well want to unfold
// explicitly, eg to more easily check the correspondence between
// the ASL and the compiled implementation of this

// Need to add range valeus for the mask if we hope to add invariants in here
unsigned long long AArch64_get_offset (unsigned long long vaddress,
				       unsigned char level) {
  
  unsigned long long offset = 0; // offset in bytes of entry from table_base
  
  switch (level) {
    case 0: offset = (vaddress & GENMASK(47,39)) >> (39-3); break;
    case 1: offset = (vaddress & GENMASK(38,30)) >> (30-3); break;
    case 2: offset = (vaddress & GENMASK(29,21)) >> (21-3); break;
    case 3: offset = (vaddress & GENMASK(20,12)) >> (12-3); break;
  }

  return offset;
}

struct TLBRecord AArch64_TranslationTableWalk_Level3(unsigned long long table_base,
						     unsigned long long vaddress) {
  unsigned long long pte; 

  unsigned long long offset; // offset in bytes of entry from table_base
  unsigned long long * table_base_ptr = (unsigned long long *)table_base;
  offset = AArch64_get_offset(vaddress, 3);
  
  // uintptr_t tbval = (uintptr_t) table_base;  
  // pte = *((unsigned long long*)(table_base + offset));
  pte = table_base_ptr[offset];
  /* 
  pte = *((unsigned long long*)(((unsigned long long)table_base) + offset));
  */
  
  switch (pte & GENMASK(1,0)) {
    case ENTRY_INVALID_0:
    case ENTRY_INVALID_2:
    case ENTRY_BLOCK:
      // invalid or fault entry
      return mkFault(vaddress);
    case ENTRY_PAGE_DESCRIPTOR: // page descriptor
      return mkTranslation(vaddress, (pte & GENMASK(47,12)) | (vaddress & GENMASK(11,0)));
  }

  return mkFault(vaddress);
}

struct LEVEL012_result AArch64_TranslationTableWalk_Level012(unsigned long long table_base, 
    unsigned char level,
    unsigned long long vaddress) {
  unsigned long long pte; 

  unsigned long long offset; // offset in bytes of entry from table_base
  unsigned long long * table_base_ptr = (unsigned long long *)table_base;
  offset = AArch64_get_offset(vaddress, level);
  
  // uintptr_t tbval = (uintptr_t) table_base;  
  // pte = *((unsigned long long*)(table_base + offset));
  pte = table_base_ptr[offset];
  /*
  pte = *((unsigned long long*)(((unsigned long long)table_base) + offset));
  */

  switch (pte & GENMASK(1,0)) {
    case ENTRY_INVALID_0:
    case ENTRY_INVALID_2:
      return mkFaultLevel012(vaddress);
    case ENTRY_BLOCK:
      switch (level) {
        case 0:
          return mkFaultLevel012(vaddress);
        case 1:
          return mkTranslationLevel012(vaddress, (pte & GENMASK(47,30)) | (vaddress & GENMASK(29,0)));
        case 2:
          return mkTranslationLevel012(vaddress, (pte & GENMASK(47,21)) | (vaddress & GENMASK(20,0)));
      }
    case ENTRY_TABLE: // recurse
      {
        unsigned long long table_base_next_phys, table_base_next_virt;
	// XXX(JK) - How can we identify the following line?
	// XXX(JK) - we need to ensure that the result of the following GENMASK value
	// should be a valid pointer... 
	/*
        table_base_next_virt = 
          (unsigned long long)hyp_phys_to_virt
           ((phys_addr_t)table_base_next_phys);
	*/
        table_base_next_phys = pte & GENMASK(47,12);
        table_base_next_virt = (unsigned long long)hyp_phys_to_virt(table_base_next_phys);
        return mkIntermediateLevel012(table_base_next_virt); 
      }
  }

  return mkFaultLevel012(vaddress);
}

struct TLBRecord AArch64_TranslationTableWalk(unsigned long long table_base,
                             unsigned long long level,
                             unsigned long long vaddress) {
        // these declarations should really be combined with their
        // initialisations below, but the compiler complains that ISO C90
        // forbids mixed declations and code

  switch (level) {
    case 0:
    case 1:
    case 2:
      {
	struct LEVEL012_result res = AArch64_TranslationTableWalk_Level012(table_base, level, vaddress);
        if (res.decision == TLB_REC) {
          return extractTLBRecord(res);
	  // return extractTLBRecord(0, 0, 0, 0, 0, 0);
        } else {
          /*
	  unsigned long long new_ptable_base
	    = (unsigned long long)copy_alloc_id(res.intermediate_address, (void*) res.intermediate_address);
            */
          unsigned long long new_ptable_base = res.intermediate_address;
          AArch64_TranslationTableWalk(new_ptable_base, level + 1, vaddress);
	  }
      break;
      }
    case 3:
      AArch64_TranslationTableWalk_Level3(table_base, vaddress);
  }

  return mkFault(vaddress);
}


/**********************************************
 * End of address translation 
**********************************************/


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
