#include <xen/config.h>
#include <xen/lib.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <asm/current.h>

#include <asm/mm.h>
#include <asm/guest_access.h>
#include <asm/p2m.h>

/*
 * If mem_access is in use it might have been the reason why get_page_from_gva
 * failed to fetch the page, as it uses the MMU for the permission checking.
 * Only in these cases we do a software-based type check and fetch the page if
 * we indeed found a conflicting mem_access setting.
 */
static int check_type_get_page(vaddr_t gva, unsigned long flag,
                               struct page_info** page)
{
    long rc;
    paddr_t ipa;
    unsigned long maddr;
    unsigned long mfn;
    xenmem_access_t xma;
    p2m_type_t t;

    rc = gva_to_ipa(gva, &ipa);
    if ( rc < 0 )
        return rc;

    /*
     * We do this first as this is faster in the default case when no
     * permission is set on the page.
     */
    rc = p2m_get_mem_access(current->domain, paddr_to_pfn(ipa), &xma);
    if ( rc < 0 )
        return rc;

    /* Let's check if mem_access limited the access. */
    switch ( xma )
    {
    default:
    case XENMEM_access_rwx:
    case XENMEM_access_rw:
        return -EFAULT;
    case XENMEM_access_n2rwx:
    case XENMEM_access_n:
    case XENMEM_access_x:
        break;
    case XENMEM_access_wx:
    case XENMEM_access_w:
        if ( flag == GV2M_READ )
            break;
        else return -EFAULT;
    case XENMEM_access_rx2rw:
    case XENMEM_access_rx:
    case XENMEM_access_r:
        if ( flag == GV2M_WRITE )
            break;
        else return -EFAULT;
    }

    /*
     * We had a mem_access permission limiting the access, but the page type
     * could also be limiting, so we need to check that as well.
     */
    maddr = p2m_lookup(current->domain, ipa, &t);
    if ( maddr == INVALID_PADDR )
        return -EFAULT;

    mfn = maddr >> PAGE_SHIFT;
    if ( !mfn_valid(mfn) )
        return -EFAULT;

    /*
     * All page types are readable so we only have to check the
     * type if writing.
     */
    if ( flag == GV2M_WRITE )
    {
        switch ( t )
        {
        case p2m_ram_rw:
        case p2m_iommu_map_rw:
        case p2m_map_foreign:
        case p2m_grant_map_rw:
        case p2m_mmio_direct:
            /* Base type allows writing, we are good to get the page. */
            break;
        default:
            return -EFAULT;
        }
    }

    *page = mfn_to_page(mfn);

    if ( unlikely(!get_page(*page, current->domain)) )
    {
        *page = NULL;
        return -EFAULT;
    }

    return 0;
}

/*
 * If mem_access is not in use, we have a fault. If mem_access is in use, do the
 * software-based type checking.
 */
static inline
int check_mem_access(vaddr_t gva, unsigned long flag, struct page_info **page)
{
    if( !current->domain->arch.p2m.access_in_use )
        return -EFAULT;

    return check_type_get_page(gva, flag, page);
}

static unsigned long raw_copy_to_guest_helper(void *to, const void *from,
                                              unsigned len, int flush_dcache)
{
    /* XXX needs to handle faults */
    unsigned offset = (vaddr_t)to & ~PAGE_MASK;

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = get_page_from_gva(current->domain, (vaddr_t) to, GV2M_WRITE);
        if ( page == NULL )
        {
            if ( check_mem_access((vaddr_t) to, GV2M_WRITE, &page) < 0 )
                return len;
        }

        p = __map_domain_page(page);
        p += offset;
        memcpy(p, from, size);
        if ( flush_dcache )
            clean_dcache_va_range(p, size);

        unmap_domain_page(p - offset);
        put_page(page);
        len -= size;
        from += size;
        to += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }

    return 0;
}

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len)
{
    return raw_copy_to_guest_helper(to, from, len, 0);
}

unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned len)
{
    return raw_copy_to_guest_helper(to, from, len, 1);
}

unsigned long raw_clear_guest(void *to, unsigned len)
{
    /* XXX needs to handle faults */
    unsigned offset = (vaddr_t)to & ~PAGE_MASK;

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = get_page_from_gva(current->domain, (vaddr_t) to, GV2M_WRITE);
        if ( page == NULL )
        {
            if ( check_mem_access((vaddr_t) to, GV2M_WRITE, &page) < 0 )
                return len;
        }

        p = __map_domain_page(page);
        p += offset;
        memset(p, 0x00, size);

        unmap_domain_page(p - offset);
        put_page(page);
        len -= size;
        to += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }

    return 0;
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    unsigned offset = (vaddr_t)from & ~PAGE_MASK;

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)(PAGE_SIZE - offset));
        struct page_info *page;

        page = get_page_from_gva(current->domain, (vaddr_t) from, GV2M_READ);
        if ( page == NULL )
        {
            if ( check_mem_access((vaddr_t) from, GV2M_READ, &page) < 0 )
                return len;
        }

        p = __map_domain_page(page);
        p += ((vaddr_t)from & (~PAGE_MASK));

        memcpy(to, p, size);

        unmap_domain_page(p);
        put_page(page);
        len -= size;
        from += size;
        to += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }
    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
