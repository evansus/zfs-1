
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>

#include <sys/zfs_vnops.h>
#include <sys/taskq.h>

#include <libkern/version.h>

#include <libkern/sysctl.h>

#include <IOKit/IOTypes.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <pexpert/pexpert.h>
#include <sys/param.h>
#include <sys/nvpair.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>

extern "C" {
  extern kern_return_t _start(kmod_info_t *ki, void *data);
  extern kern_return_t _stop(kmod_info_t *ki, void *data);
};
  __attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.lundman.zfs, "1.0.0", _start, _stop)
  __private_extern__ kmod_start_func_t *_realmain = 0;
  __private_extern__ kmod_stop_func_t  *_antimain = 0;
  __private_extern__ int _kext_apple_cc = __APPLE_CC__ ;


/*
 * Can those with more C++ experience clean this up?
 */
static void *global_c_interface = NULL;


// Define the superclass.
#define super IOService

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol, IOService)


/*
 * Some left over functions from zfs_osx.c, left as C until cleaned up
 */

extern "C" {

extern SInt32 zfs_active_fs_count;

/* Global system task queue for common use */
extern int system_taskq_size;
taskq_t	*system_taskq = NULL;




#ifdef __APPLE__
extern int
zfs_vfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp,
               user_addr_t newp, size_t newlen, __unused vfs_context_t context)
{
IOLog( "zfs_vfs_sysctl" );
    
#if 0
	int error;
	switch(name[0]) {
	case ZFS_SYSCTL_FOOTPRINT: {
		zfs_footprint_stats_t *footprint;
		size_t copyinsize;
		size_t copyoutsize;
		int max_caches;
		int act_caches;

		if (newp) {
			return (EINVAL);
		}
		if (!oldp) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (0);
		}
		copyinsize = *oldlenp;
		if (copyinsize < sizeof (zfs_footprint_stats_t)) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (ENOMEM);
		}
		footprint = kmem_alloc(copyinsize, KM_SLEEP);

		max_caches = copyinsize - sizeof (zfs_footprint_stats_t);
		max_caches += sizeof (kmem_cache_stats_t);
		max_caches /= sizeof (kmem_cache_stats_t);

		footprint->version = ZFS_FOOTPRINT_VERSION;

		footprint->memory_stats.current = zfs_footprint.current;
		footprint->memory_stats.target = zfs_footprint.target;
		footprint->memory_stats.highest = zfs_footprint.highest;
		footprint->memory_stats.maximum = zfs_footprint.maximum;

		arc_get_stats(&footprint->arc_stats);

		kmem_cache_stats(&footprint->cache_stats[0], max_caches, &act_caches);
		footprint->caches_count = act_caches;
		footprint->thread_count = zfs_threads;

		copyoutsize = sizeof (zfs_footprint_stats_t) +
		              ((act_caches - 1) * sizeof (kmem_cache_stats_t));

		error = copyout(footprint, oldp, copyoutsize);

		kmem_free(footprint, copyinsize);

		return (error);
	    }

	case ZFS_SYSCTL_CONFIG_DEBUGMSG:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_msg_buf_enabled);
		return error;

	case ZFS_SYSCTL_CONFIG_zdprintf:
#ifdef ZFS_DEBUG
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_zdprintf_enabled);
#else
		error = ENOTSUP;
#endif
		return error;
	}
#endif
	return (ENOTSUP);
}
#endif /* __APPLE__ */



void
system_taskq_fini(void)
{
    if (system_taskq)
        taskq_destroy(system_taskq);
}


#include <sys/utsname.h>
#include <string.h>

void
system_taskq_init(void)
{

    system_taskq = taskq_create("system_taskq",
                                system_taskq_size * max_ncpus,
                                minclsyspri, 4, 512,
                                TASKQ_DYNAMIC | TASKQ_PREPOPULATE);


}

/*
 * fnv_32a_str - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a string
 *
 * input:
 *	str	- string to hash
 *	hval	- previous hash value or 0 if first call
 *
 * returns:
 *	32 bit hash as a static hash type
 *
 * NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
 *  	 hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
 */
#define FNV1_32A_INIT ((uint32_t)0x811c9dc5)
uint32_t
fnv_32a_str(const char *str, uint32_t hval)
{
    unsigned char *s = (unsigned char *)str;	/* unsigned string */

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (*s) {

	/* xor the bottom with the current octet */
	hval ^= (uint32_t)*s++;

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }

    /* return our new hash value */
    return hval;
}


} // Extern "C"




bool net_lundman_zfs_zvol::init (OSDictionary* dict)
{
    bool res = super::init(dict);
IOLog("ZFS::init\n");
    global_c_interface = (void *)this;
    return res;
}


void net_lundman_zfs_zvol::free (void)
{
IOLog("ZFS::free\n");
    global_c_interface = NULL;
    super::free();
}


IOService* net_lundman_zfs_zvol::probe (IOService* provider, SInt32* score)
{
    IOService *res = super::probe(provider, score);
IOLog("ZFS::probe\n");
    return res;
}

bool net_lundman_zfs_zvol::start (IOService *provider)
{
    bool res = super::start(provider);

IOLog("ZFS: Loading module ... \n");

	/*
	 * Initialize znode cache, vnode ops, etc...
	 */
	zfs_znode_init();

	/*
	 * Initialize /dev/zfs, this calls spa_init->dmu_init->arc_init-> etc
	 */
	zfs_ioctl_init();

	///sysctl_register_oid(&sysctl__debug_maczfs);
	//sysctl_register_oid(&sysctl__debug_maczfs_stalk);

    zfs_vfsops_init();

    /*
     * When is the best time to start the system_taskq? It is strictly
     * speaking not used by SPL, but by ZFS. ZFS should really start it?
     */
    system_taskq_init();


    /*
     * hostid is left as 0 on OSX, and left to be set if developers wish to
     * use it. If it is 0, we will hash the hardware.uuid into a 32 bit
     * value and set the hostid.
     */
    if (!zone_get_hostid(NULL)) {
      uint32_t myhostid = 0;
      IORegistryEntry *ioregroot =  IORegistryEntry::getRegistryRoot();
      if(ioregroot) {
        //IOLog("ioregroot is '%s'\n", ioregroot->getName(gIOServicePlane));
        IORegistryEntry *macmodel = ioregroot->getChildEntry(gIOServicePlane);
        if(macmodel) {
          //IOLog("macmodel is '%s'\n", macmodel->getName(gIOServicePlane));
          OSObject *ioplatformuuidobj;
          //ioplatformuuidobj = ioregroot->getProperty("IOPlatformUUID", gIOServicePlane, kIORegistryIterateRecursively);
          ioplatformuuidobj = macmodel->getProperty(kIOPlatformUUIDKey);
          if(ioplatformuuidobj) {
            OSString *ioplatformuuidstr = OSDynamicCast(OSString, ioplatformuuidobj);
            //IOLog("IOPlatformUUID is '%s'\n", ioplatformuuidstr->getCStringNoCopy());

            myhostid = fnv_32a_str(ioplatformuuidstr->getCStringNoCopy(),
                                   FNV1_32A_INIT);

            sysctlbyname("kern.hostid", NULL, NULL, &myhostid, sizeof(myhostid));
            printf("ZFS: hostid set to %08x from UUID '%s'\n",
                   myhostid, ioplatformuuidstr->getCStringNoCopy());
          }
        }
      }
    }
    
    /* Check if ZFS should try to mount root */
    if( ( res && zfs_check_mountroot() ) == true ) {
        /* Looks good, give it a go */
        res = zfs_mountroot();
    }

    return res;
}

void net_lundman_zfs_zvol::stop (IOService *provider)
{


#if 0
  // You can not stop unload :(
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    zvol_busy()) {

      IOLog("ZFS: Can not unload as we have filesystems mounted.\n");
      return;
	}
#endif
    
IOLog("ZFS: Attempting to unload ...\n");

    super::stop(provider);


    system_taskq_fini();

    zfs_ioctl_fini();
    zvol_fini();
    zfs_vfsops_fini();
    zfs_znode_fini();

	//sysctl_unregister_oid(&sysctl__debug_maczfs_stalk);
    //	sysctl_unregister_oid(&sysctl__debug_maczfs);

IOLog("ZFS: Unloaded module\n");

}

bool net_lundman_zfs_zvol::zfs_check_mountroot()
{
    
    /*
     * Check if the kext is loading during early boot
     * and/or check if root is mounted (IORegistry?)
     * Use PE Boot Args to determine the root pool name.
     */
    const int arglen = 256;
    char zfs_boot[arglen];
    bool result = false;

    PE_parse_boot_argn( "zfs_boot", &zfs_boot, sizeof(zfs_boot) );
IOLog( "Raw zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    
    result =    ( strlen(zfs_boot) > 0 );
    
    if ( !result ) {
        PE_parse_boot_argn( "rd", &zfs_boot, sizeof(zfs_boot) );
IOLog( "Raw rd: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    }
    if ( !result ) {
        PE_parse_boot_argn( "rootdev", &zfs_boot, sizeof(zfs_boot) );
IOLog( "Raw rootdev: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    }
    
//IOSleep( 2000 );
    
    if ( result ) {
        IOLog( "Got zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    } else {
        IOLog( "No zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
    }
    
    return result;
    
}

/* TO DO */
/* Move this to zfs_boot.cpp */
#include <sys/zfs_ioctl.h>

bool net_lundman_zfs_zvol::zfs_mountroot(   /*vfs_t *vfsp, enum whymountroot why*/ )
{
    
    /*              EDITORIAL / README
     *
     * The filesystem that we mount as root is defined in the
     * boot property "zfs_boot" with a format of
     * "poolname/root-dataset-name".
     * You may also use the options "rd=zfs:pool/dataset"
     *  or "rootdev=zfs:pool/dataset"
     *
     * Valid entries: "rpool", "tank/fish",
     *  "sys/ROOT/BootEnvironment", and so on.
     *
     *  see /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
     *  and ${PREFIX}/share/zfs/com.apple.Boot.plist for examples
     *
     * Note that initial boot support uses ZVOLs formatted
     * as (Mac-native) Journaled HFS+
     * In this case the bootfs will be a ZVOL, which cannot
     * be set via "zpool set bootfs=pool/zvol"
     *
     * Using ZFS datasets as root will require an additional
     * hack to trick the xnu kernel.
     *
     * Candidate is creating a (blank) ramdisk in chosen/RamDisk,
     * then forcible root-mount, possibly using an overlay.
     * Other options may include grub2+zfs, Chameleon, Chimera, etc.
     *
     */
    
    
    /*
     *           TO DO -- TO DO -- TO DO
     *
     * Use PE Boot Args to determine the root pool name.
     *
     * future: Use IORegistry to locate vdevs.
     *
     * Call functions in vdev_disk.c or spa_boot.c
     * to locate the pool, import it.
     *
     * Case 1: Present zvol for the Root volume
     *
     * Case 2: Similar to meklort's FSRoot method,
     * register vfs_fsadd, and mount root;
     * mount the bootfs dataset as a union mount on top
     * of a ramdisk if necessary.
     */
    
    IORegistryIterator * registryIterator = 0;
    IORegistryEntry * currentEntry = 0;
    OSOrderedSet * allDisks = 0;
    OSDictionary * matchingDictionary = 0;
    OSBoolean * matchBool = 0;
    
    char * diskName = 0;
    char * diskPath = 0;

    const int arglen = 256;
    int split = 0;
    UInt64 labelSize;
    char * strptr = NULL;
    char zfs_boot[arglen];
    char zfs_pool[arglen];
    char zfs_root[arglen];
    bool result = false;
    
    PE_parse_boot_argn( "zfs_boot", &zfs_boot, sizeof(zfs_boot) );
    
    result =    ( strlen(zfs_boot) > 0 );
    
    if ( !result ) {
        PE_parse_boot_argn( "rd", &zfs_boot, sizeof(zfs_boot) );
    }
    if ( !result ) {
        PE_parse_boot_argn( "rootdev", &zfs_boot, sizeof(zfs_boot) );
    }

    if ( !result ) {
IOLog( "Invalid zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        return false;
    }
    
    /*
     char *slashp;
     uint64_t objnum;
     int error;
     
     if (*bpath == 0 || *bpath == '/')
     return (EINVAL);
     
     (void) strcpy(outpath, bpath);
     
     slashp = strchr(bpath, '/');
     
     // if no '/', just return the pool name
     if (slashp == NULL) {
     return (0);
     }
     
     // if not a number, just return the root dataset name
     if (str_to_uint64(slashp+1, &objnum)) {
     return (0);
     }
     
     *slashp = '\0';
     error = dsl_dsobj_to_dsname(bpath, objnum, outpath);
     *slashp = '/';
     
     return (error);
     
     //			(void) strlcat(name, "@", MAXPATHLEN);
     
     */
    
    // Error checking, should be longer than 1 character and null terminated
    strptr = strchr( zfs_boot, '\0' );
    if ( strptr == NULL ) {
        IOLog( "Invalid zfs_boot: Not null terminated : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( 2000 );
    }
    
    // Error checking, should be longer than 1 character
    if ( strlen(strptr) == 1 ) {
        IOLog( "Invalid zfs_boot: Only null character : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( 2000 );
    } else {
        IOLog( "Valid zfs_boot: [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( 2000 );
    }
    
    // Find first '/' in the boot arg
    strptr = strchr( zfs_boot, '/' );
    
    // If leading '/', return error
    if ( strptr == (zfs_boot) ) {
        IOLog( "Invalid zfs_boot: starts with '/' : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( 2000 );
        strptr = NULL;
        return false;
    }
    
    // If trailing '/', return error
    if ( strptr == ( zfs_boot + strlen(zfs_boot) - 1 )  ) {
        IOLog( "Invalid zfs_boot: ends with '/' : [%llu] {%s}\n", (uint64_t)strlen(zfs_boot), zfs_boot );
        IOSleep( 2000 );
        strptr = NULL;
        return false;
    }
    
    //    split = strlen(zfs_boot) - strlen(strptr);
    
    //    if ( split > 0 && split < strlen(zfs_boot) ) {
    if ( strptr > zfs_boot ) {
        strlcpy( zfs_pool, zfs_boot, split-1 );
        strlcpy( zfs_root, strptr, strlen(strptr) );
    } else {
        strlcpy( zfs_pool, zfs_boot, strlen(zfs_boot) );
        strlcpy( zfs_root, "\0", 1 );
    }
    
    // Find last @ in zfs_root ds
    strptr = strrchr( zfs_root, '@' );
    
    //    split = strlen(zfs_root) - strlen(strptr);
    
    //    if ( split > 0 && split < strlen(zfs_boot) ) {
    if ( strptr > zfs_root ) {
        strptr += split;
        strlcpy( zfs_root, strptr, split );
    }
    
IOLog( "Will attempt to import zfs_pool: [%llu] %s", (uint64_t)strlen(zfs_pool), zfs_pool );
IOSleep( 2000 );

IOLog( "Will attempt to mount zfs_root:  [%llu] %s", (uint64_t)strlen(zfs_root), zfs_root );
IOSleep( 10000 );
    
    result = ( strlen(zfs_pool) > 0 );
    
    strptr = NULL;

    /* First create a matching dictionary for all IOMedia devices */
    matchingDictionary = IOService::resourceMatching("IOMedia");
    if(!matchingDictionary) {
        IOLog( "ZFS: Could not get resource matching dict\n" );
        /* clean up */
        matchingDictionary = 0;
        return false;
    }
    
    /*
     * We want to match on all disks or volumes that
     * do not contain a partition map / raid / LVM
     */
    matchBool = OSBoolean::withBoolean(true);
    if (!matchBool) {
        IOLog( "could not match vdev devices in IOKit");
        /* clean up */
        matchingDictionary->release();
        matchingDictionary = 0;
        matchBool = 0;
        return false;
    }

    /* Add the 'Leaf' criteria to the matching dictionary */
    matchingDictionary->setObject( kIOMediaLeafKey, matchBool );
    if (matchBool) {
        /* clean up */
        matchBool->release();
        matchBool = 0;
    }
    
    /* Pass the dictionary as a request for resources */
    registryIterator = ((IORegistryIterator *) IOService::getMatchingServices(matchingDictionary));
    if (matchingDictionary) {
        /* clean up */
        matchingDictionary->release();
        matchingDictionary = 0;
    }
    
    /*
     * Because the IORegistry could be changed before iterateAll
     * finishes copying data into the ordered set, check if the
     * IORegistry has been invalidated and start over if needed.
     * This typically completes in one loop anyway, but is the
     * recommended way to fetch results.
     */
    do {
        /*
         * If there is an invalid set from the last run,
         * make sure to release it
         */
        if(allDisks) {
            /* clean up */
            allDisks->release();
            allDisks = 0;
        }
        
        /* Grab all matching records as fast as possible */
        allDisks = registryIterator->iterateAll();
        
    } while ( ! registryIterator->isValid() );
    
    if (registryIterator) {
        /* clean up */
        registryIterator->release();
        registryIterator = 0;
    }
    
    /* Loop through all the items in allDisks */
    while ( allDisks->getCount() > 0 ) {
        
        /* 
         * Grab the first object in the set.
         * (could just as well be the last object)
         */
        currentEntry = OSDynamicCast( IORegistryEntry, allDisks->getFirstObject() );
        
        if(!currentEntry) {
            IOLog( "Error checking vdev disks\n" );
            /* clean up */
            currentEntry = 0;
            allDisks->release();
            allDisks = 0;
            return false;
        }

        /* Remove current item from ordered set */
        allDisks->removeObject( currentEntry );
        
        if (!currentEntry) {
            IOLog( "Error checking vdev disks\n" );
            /* clean up */
            currentEntry = 0;
            allDisks->release();
            allDisks = 0;
            return false;
        }
        
    
    //        if(bsdnameosobj) {
        OSObject *bsdnameosobj =    currentEntry->getProperty(kIOBSDNameKey,
                                                                  gIOServicePlane,
                                                                  kIORegistryIterateRecursively);
        OSString* bsdnameosstr =    OSDynamicCast(OSString, bsdnameosobj);
        IOLog("zfs_mountroot: bsd name is '%s'\n", bsdnameosstr->getCStringNoCopy());
        
        strncpy( diskPath, bsdnameosstr->getCStringNoCopy(), bsdnameosstr->getLength() );
        
        /* Start with '/dev' */
        strncpy( diskPath, "/dev", 4 );
        /*
         * Add "r" before the BSD node name from the I/O Registry
         * to specify the raw disk node. The raw disk node receives
         * I/O requests directly and does not go through the
         * buffer cache.
         */
        strncat( diskPath, "r", 1 );
        strncat( diskPath, diskName, strlen(diskName));
            
        result = (strlen(diskPath) > 0);
        
        if(!result) {
IOLog( "Couldn't get BSD path for %s\n", diskName );
/* clean up */
        }
            
IOLog( "BSD path: %s\n", diskPath );
IOSleep( 1000 );
            
        /*
         *
         * Finally, check the disk for bootpool nvlist
         *
         * get vdev nvlist from disk
         *
         * import
         *
         * break from loop (and clean up) on success
         *
         */
        
        IOMedia * currentDisk = OSDynamicCast(IOMedia, currentEntry);
        IOBufferMemoryDescriptor* buffer = 0;
        nvlist_t * config = 0;

        nvlist_t *nvtop, *nvroot;
        uint64_t pgid, guid;
        
        char * pool_name;
        vdev_label_t * label;
        uint64_t s, size;
        int l;
        int error = -1;
        
        // Determine whether this media is formatted.
        if ( currentDisk->isFormatted() != true ) {
            dprintf("zfs_mountroot: Disk %s not formatted", diskName);
            goto nextDisk;
        }
        
        //error = ((IOMedia*)currentEntry)->open(this,0,kIOStorageAccessReader);
        error = currentDisk->open(this,0,kIOStorageAccessReader);
        
        /* If the disk could not be opened, skip to the next one */
        if (error) {
            dprintf("zfs_mountroot: Disk %s couldn't be opened for reading", diskName);
            goto nextDisk;
        }
        
        /* Get size */
        s = currentDisk->getSize();
        
        if( s <= 0 ) {
            dprintf("zfs_mountroot: Couldn't get size of disk %s", diskName);
        }
        
        // Allocate a vdev_label_t-sized buffer to hold data read from disk.
        buffer = IOBufferMemoryDescriptor::withCapacity(sizeof (vdev_label_t), kIODirectionInOut);
        
        if (buffer == NULL) {
            dprintf("zfs_mountroot: Couldn't allocate a memory buffer");
            goto nextDisk;
        }
        
        size = P2ALIGN_TYPED(s, sizeof (vdev_label_t), uint64_t);
        label = (vdev_label_t*)kmem_alloc(sizeof (vdev_label_t), KM_SLEEP);
        
        config = NULL;
        for (l = 0; l < VDEV_LABELS; l++) {
            uint64_t offset, state, txg = 0;
            
            /* read vdev label */
            offset = vdev_label_offset(size, l, 0);
            
//                if (vdev_disk_iokit_physio(vd_lh, (caddr_t)label,
//                                           VDEV_SKIP_SIZE + VDEV_PHYS_SIZE, offset, B_READ) != 0) {

            labelSize = VDEV_SKIP_SIZE + VDEV_PHYS_SIZE;
            
            if( currentDisk->read(this, offset, buffer, NULL,
                                  &labelSize) != kIOReturnSuccess ) {
                
                (void) currentDisk->close(this,kIOStorageAccessReader);
                nvlist_free(config);
                config = NULL;
//                    goto nextDisk;
                continue;
            }
            
            (void) currentDisk->close(this,kIOStorageAccessReader);
            
            if( buffer->readBytes(0,label,buffer->getLength()) == 0 ) {
dprintf("zfs_mountroot: Failed to copy from memory buffer to label_t");
                goto nextDisk;
            }
            
            if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
                              sizeof (label->vl_vdev_phys.vp_nvlist), &config, 0) != 0) {
                config = NULL;
                continue;
            }

            /* Check the pool_name to see if it matches zfs_boot */
            if ((nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
                                     &pool_name) != 0 || strncmp(pool_name,zfs_pool,strlen(zfs_pool)) ) ) {
                nvlist_free(config);
                config = NULL;
                continue;
            }
            
            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
                                     &state) != 0 || state >= POOL_STATE_DESTROYED) {
                nvlist_free(config);
                config = NULL;
                continue;
            }

            if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
                                     &txg) != 0 || txg == 0) {
                nvlist_free(config);
                config = NULL;
                continue;
            }
            
            break;
        }
        
        kmem_free(label, sizeof (vdev_label_t));

        if (config == NULL)
            error = SET_ERROR(EIDRM);
            
        /*
         * Add this top-level vdev to the child array.
         */
        VERIFY(nvlist_lookup_nvlist(config,
                                    ZPOOL_CONFIG_VDEV_TREE, &nvtop) == 0);
        VERIFY(nvlist_lookup_uint64(config,
                                    ZPOOL_CONFIG_POOL_GUID, &pgid) == 0);
        VERIFY(nvlist_lookup_uint64(config,
                                    ZPOOL_CONFIG_GUID, &guid) == 0);
        
        /*
         * Put this pool's top-level vdevs into a root vdev.
         */
        VERIFY(nvlist_alloc(&nvroot,
                            NV_UNIQUE_NAME, KM_SLEEP) == 0);
        VERIFY(nvlist_add_string(nvroot,
                                 ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT) == 0);
        VERIFY(nvlist_add_uint64(nvroot,
                                 ZPOOL_CONFIG_ID, 0ULL) == 0);
        VERIFY(nvlist_add_uint64(nvroot,
                                 ZPOOL_CONFIG_GUID, pgid) == 0);
        VERIFY(nvlist_add_nvlist_array(nvroot,
                                       ZPOOL_CONFIG_CHILDREN, &nvtop, 1) == 0);
        
        /*
         * Replace the existing vdev_tree with the new root vdev in
         * this pool's configuration (remove the old, add the new).
         */
        VERIFY(nvlist_add_nvlist(config,
                                 ZPOOL_CONFIG_VDEV_TREE, nvroot) == 0);
        nvlist_free(nvroot);

        /* If the rootlabel has been found, try to import the pool */
        if ( error != 0 && config ) {
            
            spa_import(pool_name, config,  NULL, ZFS_IMPORT_VERBATIM );
/* 
* (ZFS_IMPORT_NORMAL | ZFS_IMPORT_VERBATIM |
*  ZFS_IMPORT_ANY_HOST | ZFS_IMPORT_MISSING_LOG |
*  ZFS_IMPORT_ONLY )
*/
        }
        
    nextDisk:
        /* clean up */
        nvlist_free(config);
        if( buffer )
            buffer->release();
        buffer = 0;
        
        currentDisk = 0;
        if( currentEntry )
            currentEntry->release();
        currentEntry = 0;

    }
    
    /* Final clean up */
    if( allDisks ) {
        /* clean up */
        allDisks->release();
        allDisks = 0;
    }
}

IOReturn net_lundman_zfs_zvol::doEjectMedia(void *arg1)
{
  zvol_state_t *nub = (zvol_state_t *)arg1;
IOLog("block svc ejecting\n");
  if(nub) {

    // Only 10.6 needs special work to eject
    if ((version_major == 10) &&
	(version_minor == 8))
      destroyBlockStorageDevice(nub);

  }

IOLog("block svc ejected\n");
  return kIOReturnSuccess;
}



bool net_lundman_zfs_zvol::createBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = false;

    if (!zv) goto bail;

IOLog("createBlock size %llu\n", zv->zv_volsize);

    // Allocate a new IOBlockStorageDevice nub.
    nub = new net_lundman_zfs_zvol_device;
    if (nub == NULL)
        goto bail;

    // Call the custom init method (passing the overall disk size).
    if (nub->init(zv) == false)
        goto bail;

    // Attach the IOBlockStorageDevice to the this driver.
    // This call increments the reference count of the nub object,
    // so we can release our reference at function exit.
    if (nub->attach(this) == false)
        goto bail;

    // Allow the upper level drivers to match against the IOBlockStorageDevice.
    /*
     * We here use Synchronous, so that all services are attached now, then
     * we can go look for the BSDName. We need this to create the correct
     * symlinks.
     */
    nub->registerService( kIOServiceSynchronous);

    nub->getBSDName();

    if ((version_major != 10) &&
	(version_minor != 8))
      zvol_add_symlink(zv, &zv->zv_bsdname[1], zv->zv_bsdname);

    result = true;

 bail:
    // Unconditionally release the nub object.
    if (nub != NULL)
        nub->release();

   return result;
}

bool net_lundman_zfs_zvol::destroyBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = true;

    if (zv->zv_iokitdev) {

IOLog("removeBlockdevice\n");

      nub = static_cast<net_lundman_zfs_zvol_device*>(zv->zv_iokitdev);

      zv->zv_iokitdev = NULL;
      zv = NULL;

      nub->terminate();
    }

    return result;
}

bool net_lundman_zfs_zvol::updateVolSize(zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    //bool            result = true;

    // Is it ok to keep a pointer reference to the nub like this?
    if (zv->zv_iokitdev) {
      nub = static_cast<net_lundman_zfs_zvol_device*>(zv->zv_iokitdev);

      //IOLog("Attempting to update volsize\n");
      nub->retain();
      nub->registerService();
      nub->release();
    }
    return true;
}

/*
 * Not used
 */
IOByteCount net_lundman_zfs_zvol::performRead (IOMemoryDescriptor* dstDesc,
                                               UInt64 byteOffset,
                                               UInt64 byteCount)
{
  IOLog("performRead offset %llu count %llu\n", byteOffset, byteCount);
    return dstDesc->writeBytes(0, (void*)((uintptr_t)m_buffer + byteOffset),
                               byteCount);
}

/*
 * Not used
 */
IOByteCount net_lundman_zfs_zvol::performWrite (IOMemoryDescriptor* srcDesc,
                                                UInt64 byteOffset,
                                                UInt64 byteCount)
{
  IOLog("performWrite offset %llu count %llu\n", byteOffset, byteCount);
    return srcDesc->readBytes(0, (void*)((uintptr_t)m_buffer + byteOffset), byteCount);
}


/*
 * C language interfaces
 */

int zvolCreateNewDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->createBlockStorageDevice(zv);
    return 0;
}

int zvolRemoveDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->destroyBlockStorageDevice(zv);
    return 0;
}

int zvolSetVolsize(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->updateVolSize(zv);
    return 0;
}


uint64_t zvolIO_kit_read(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_read offset %p count %llx to offset %llx\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->writeBytes(offset,
                                                           (void *)address,
                                                           len);
  return done;
}

uint64_t zvolIO_kit_write(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_write offset %p count %llx to offset %llx\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->readBytes(offset,
                                                          (void *)address,
                                                          len);
  return done;
}
