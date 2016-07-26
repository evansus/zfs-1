/*
 * ZFSDataset - proxy disk for legacy and com.apple.devicenode mounts.
 */

//extern "C" {
//}

#include <sys/ZFSDataset.h>
#include <sys/spa_impl.h>
#include <sys/ZFSPool.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#define	DLOGFUNC()	do {			\
	IOLog("ZFSDataset %s\n", __func__);	\
} while (0);

#ifdef dprintf
#undef dprintf
#endif
#define	dprintf		IOLog

int
zfs_dataset_proxy_get_osname(const char *in, char *out, int len)
{
	ZFSDataset *dataset;
	IOService *service;
	OSDictionary *matching;
	OSString *osstr;
	const char *osname;
	const char *bsdname;
	bool ret;

	/* Validate arguments */
	if (!in || !out || len == 0) {
		dprintf("%s invalid argument\n", __func__);
		return (EINVAL);
	}
	if (strncmp(in, "/dev/", 5) == 0) {
		bsdname = in + 5;
	} else {
		bsdname = in;
	}
	if (strncmp(bsdname, "disk", 4) != 0) {
		dprintf("%s invalid bsdname %s from %s\n", __func__, bsdname, in);
		return (EINVAL);
	}
	if ((osstr = OSString::withCString(bsdname)) == NULL) {
		dprintf("%s couldn't alloc string\n", __func__);
		return (ENOMEM);
	}

	/* Get matching dictionary for ZFSDataset class */
	if ((matching = IOService::serviceMatching("ZFSDataset")) == NULL) {
		dprintf("%s couldn't get match dictionary\n", __func__);
		osstr->release();
		return (ENOMEM);
	}

	/* Add match key for BSD disk name from in argument */
	ret = matching->setObject(kIOBSDNameKey, osstr);
	osstr->release();
	osstr = 0;
	if (ret == false) {
		dprintf("%s couldn't match on bsdname\n", __func__);
		matching->release();
		return (ENOMEM);
	}

	/* Get matching service, should only be one */
	service = IOService::copyMatchingService(matching);
	matching->release();
	matching = 0;
	if (service == NULL) {
		dprintf("%s no matching service\n", __func__);
		return (ENOENT);
	}
	if ((dataset = OSDynamicCast(ZFSDataset, service)) == NULL) {
		dprintf("%s match couldn't be cast\n", __func__);
		service->release();
		return (ENOENT);
	}

	/* Grab and retain the ZFS Dataset property string */
	osstr = OSDynamicCast(OSString,
	    dataset->getProperty(kZFSDatasetNameKey));
	if (osstr) osstr->retain();
	dataset->release();

	if (!osstr) {
		dprintf("%s couldn't get datset name from proxy\n", __func__);
		return (ENXIO);
	}

	/* Get pointer to C string */
	osname = osstr->getCStringNoCopy();
	if (!osname) {
		dprintf("%s invalid OSString\n", __func__);
		return (ENXIO);
	}

	/* Finally, zero the out buffer and copyout the osname */
	bzero(out, len);
	snprintf(out, len, "%s", osname);
	osstr->release();

	dprintf("%s copied out %s\n", __func__, osname);
	return (0);
}

/*
 * Input:
 * osname: dataset name e.g. pool/dataset
 * Return:
 * 0 if exists, positive int on error or missing.
 */
int
spa_iokit_dataset_proxy_exists(const char *osname)
{
	IOService *service;
	OSDictionary *matching;
	const OSSymbol *nameSymbol, *classSymbol;

	if (!osname || osname[0] == '\0' ||
	    (nameSymbol = OSSymbol::withCString(osname)) == NULL) {
		dprintf("%s invalid osname\n", __func__);
		return (EINVAL);
	}

	classSymbol = OSSymbol::withCString("ZFSDataset");
	if (!classSymbol) {
		dprintf("%s missing class name\n", __func__);
		nameSymbol->release();
		return (EINVAL);
	}

	matching = IOService::serviceMatching(classSymbol);
	if (!matching || matching->setObject(kZFSDatasetNameKey,
	    nameSymbol) == false) {
		dprintf("%s couldn't setup matching\n", __func__);
		nameSymbol->release();
		classSymbol->release();
		return (ENOMEM);
	}
	nameSymbol->release();
	nameSymbol = 0;
	classSymbol->release();
	classSymbol = 0;

	service = IOService::copyMatchingService(matching);
	matching->release();
	matching = 0;
	if (!service) {
		dprintf("%s no matching service\n", __func__);
		return (ENOENT);
	}

	/* Verify we can cast matching service */
	if (OSDynamicCast(ZFSDataset, service) != NULL) {
		service->release();
		return (0);
	}

	service->release();
	return (ENOENT);
}

//spa_iokit_dataset_proxy_create(nvlist_t *config)
int
spa_iokit_dataset_proxy_create(const char *osname)
{
	spa_t *spa;
	ZFSPool *pool = 0;
	ZFSDataset *dataset;

	if (!osname || osname[0] == '\0') {
		dprintf("%s missing dataset argument\n", __func__);
		return (EINVAL);
	}

	mutex_enter(&spa_namespace_lock);
	spa = spa_lookup(osname);
	if (spa && spa->spa_iokit_proxy) {
		pool = spa->spa_iokit_proxy->proxy;
		if (pool) pool->retain();
	}
	mutex_exit(&spa_namespace_lock);

	/* Need a pool proxy to attach to */
	if (!pool) {
		dprintf("%s couldn't get pool proxy\n", __func__);
		return (EINVAL);
	}

	/* Returns 0 for existing */
	if (spa_iokit_dataset_proxy_exists(osname) == 0) {
		dprintf("%s %s already has a proxy device\n",
		    __func__, osname);
		pool->release();
		return (EBUSY);
	}

	/* Create new proxy object */
	dataset = ZFSDataset::withDatasetName(osname);
	if (!dataset) {
		pool->release();
		return (ENOMEM);
	}

	pool->lockForArbitration();
	if (dataset->attach(pool) == false) {
		dprintf("%s attach failed\n", __func__);
		dataset->release();
		pool->unlockForArbitration();
		pool->release();
		return (ENXIO);
	}
	pool->unlockForArbitration();

	if (dataset->start(pool) == false) {
		dprintf("%s start failed\n", __func__);
		dataset->detach(pool);
		dataset->release();
		pool->release();
		return (ENXIO);
	}
	pool->release();
	pool = 0;

	dataset->registerService(kIOServiceAsynchronous);
	/* XXX Check dataset list for existing */
	  /* XXX lock list
	   * walk, break on match
	   * unlock
	   */
	/* XXX Make new dataset proxy if no match*/
	/* XXX Add to list, or drop if race lost */
	  /* XXX lock list
	   * walk, break on match
	   * insert if no match
	   * unlock
	   * if match, release created proxy
	   */
	/* XXX registerService on matched or new proxy */

	return (0);
}

int
spa_iokit_dataset_proxy_destroy(char *osname)
{
	/* XXX Find dataset proxy and terminate
	 * lock list
	 * walk, break on match
	 * unlock list
	 * terminate if match
	 * return status
	 */
	return (ENOTSUP);
}

OSDefineMetaClassAndStructors(ZFSDataset, IOMedia);

#if 0
/* XXX Only for debug tracing */
bool
ZFSDataset::open(IOService *client,
	    IOOptionBits options, IOStorageAccess access)
{
	bool ret;
	DLOGFUNC();

	ret = IOMedia::open(client, options, access);

	dprintf("ZFSDataset %s ret %d\n", __func__, ret);
	return (ret);
}

bool
ZFSDataset::isOpen(const IOService *forClient) const
{
	IOLog("ZFSDataset %s\n", __func__);
	return (false);
}

void
ZFSDataset::close(IOService *client,
	    IOOptionBits options)
{
	DLOGFUNC();
	IOMedia::close(client, options);
}

bool
ZFSDataset::handleOpen(IOService *client,
	    IOOptionBits options, void *access)
{
	bool ret;
	DLOGFUNC();

	ret = IOMedia::handleOpen(client, options, access);

	dprintf("ZFSDataset %s ret %d\n", __func__, ret);
	return (ret);
}

bool
ZFSDataset::handleIsOpen(const IOService *client) const
{
	bool ret;
	DLOGFUNC();

	ret = IOMedia::handleIsOpen(client);

	dprintf("ZFSDataset %s ret %d\n", __func__, ret);
	return (ret);
}

void
ZFSDataset::handleClose(IOService *client,
    IOOptionBits options)
{
	DLOGFUNC();
	IOMedia::handleClose(client, options);
}
#endif

bool
ZFSDataset::attach(IOService *provider)
{
	DLOGFUNC();
	return (super::attach(provider));
}

void
ZFSDataset::detach(IOService *provider)
{
	DLOGFUNC();
	super::detach(provider);
}

bool
ZFSDataset::start(IOService *provider)
{
	DLOGFUNC();
	return (super::start(provider));
}

void
ZFSDataset::stop(IOService *provider)
{
	DLOGFUNC();
	super::stop(provider);
}

bool
ZFSDataset::init(UInt64 base, UInt64 size,
    UInt64 preferredBlockSize,
    IOMediaAttributeMask attributes,
    bool isWhole, bool isWritable,
    const char *contentHint,
    OSDictionary *properties)
{
	DLOGFUNC();
	return (super::init(base, size, preferredBlockSize,
	    attributes, isWhole, isWritable, contentHint,
	    properties));
}

void
ZFSDataset::free()
{
	DLOGFUNC();
	super::free();
}

ZFSDataset *
ZFSDataset::withDatasetName(const char *name)
{
	ZFSDataset *dataset;
	size_t size;
	bool isWritable;

	DLOGFUNC();

	if (!name || name[0] == '\0') {
		dprintf("%s missing name\n", __func__);
		return (NULL);
	}

	dataset = new ZFSDataset;
	if (!dataset) {
		dprintf("%s allocation failed\n", __func__);
		return (NULL);
	}

	/* XXX Make up a size and read/write for now XXX */
	size = (1<<30);
	isWritable = true;
#if 0
ZFSDataset::init(UInt64 base, UInt64 size,
    UInt64 preferredBlockSize,
    IOMediaAttributeMask attributes,
    bool isWhole, bool isWritable,
    const char *contentHint,
    OSDictionary *properties)
#endif
	if (dataset->init(/* base */ 0, size, DEV_BSIZE,
	    /* attributes */ 0, /* isWhole */ true, isWritable,
	    kZFSContentHint, /* properties */ NULL) == false) {
		dprintf("%s init failed\n", __func__);
		dataset->release();
		return (NULL);
	}

	if (dataset->setDatasetName(name) == false) {
		dprintf("%s invalid name\n", __func__);
		dataset->release();
		return (NULL);
	}

	return (dataset);
}

void
ZFSDataset::read(IOService *client,
    UInt64 byteStart, IOMemoryDescriptor *buffer,
    IOStorageAttributes *attributes,
    IOStorageCompletion *completion)
{
	IOByteCount total, cur_len, done = 0;
	addr64_t cur;

	DLOGFUNC();
	if (!buffer) {
		if (completion) complete(completion, kIOReturnInvalid, 0);
		return;
	}

	total = buffer->getLength();

	/* XXX Get each physical segment of the buffer and zero it */
	while (done < total) {
		cur_len = 0;
		cur = buffer->getPhysicalSegment(done, &cur_len);
		if (cur == 0) break;
		if (cur_len != 0) bzero_phys(cur, cur_len);
		done += cur_len;
		ASSERT3U(done, <=, total);
	}
	ASSERT3U(done, ==, total);

	//if (!completion || !completion->action) {
	if (!completion) {
		dprintf("ZFSDataset %s invalid completion\n", __func__);
		return;
	}

//	(completion->action)(completion->target, completion->parameter,
//	    kIOReturnSuccess, total);
	complete(completion, kIOReturnSuccess, total);
}

void
ZFSDataset::write(IOService *client,
    UInt64 byteStart, IOMemoryDescriptor *buffer,
    IOStorageAttributes *attributes,
    IOStorageCompletion *completion)
{
	IOByteCount total;
	DLOGFUNC();

	if (!buffer) {
		if (completion) complete(completion, kIOReturnInvalid);
		return;
	}

	total = buffer->getLength();

	//if (!completion || !completion->action) {
	if (!completion) {
		dprintf("ZFSDataset %s invalid completion\n", __func__);
		return;
	}

	/* XXX No-op, just return success */
//	(completion->action)(completion->target, completion->parameter,
//	    kIOReturnSuccess, total);
	complete(completion, kIOReturnSuccess, total);
}

volatile SInt64 num_sync = 0;

IOReturn
ZFSDataset::synchronize(IOService *client,
    UInt64 byteStart, UInt64 byteCount,
    IOStorageSynchronizeOptions options)
{
	SInt64 cur_sync = 0;
	DLOGFUNC();
	cur_sync = OSIncrementAtomic64(&num_sync);
	dprintf("sync called %lld times\n", cur_sync);

	/* XXX Needs to report success for mount_common() */
	return (kIOReturnSuccess);
	//return (kIOReturnUnsupported);
	//return (super::synchronize(client, byteStart, byteCount, options));
}

IOReturn
ZFSDataset::unmap(IOService *client,
    IOStorageExtent *extents, UInt32 extentsCount,
    IOStorageUnmapOptions options)
{
	DLOGFUNC();
	return (kIOReturnUnsupported);
	//return (super::unmap(client, extents, extentsCount, options));
}

IOStorage *
ZFSDataset::copyPhysicalExtent(IOService *client,
    UInt64 *byteStart, UInt64 *byteCount)
{
	DLOGFUNC();
	return (0);
	//return (super::copyPhysicalExtent(client, byteStart, byteCount));
}

void
ZFSDataset::unlockPhysicalExtents(IOService *client)
{
	DLOGFUNC();
	//super::unlockPhysicalExtents(client);
}

IOReturn
ZFSDataset::setPriority(IOService *client,
    IOStorageExtent *extents, UInt32 extentsCount,
    IOStoragePriority priority)
{
	DLOGFUNC();
	return (kIOReturnUnsupported);
	//return (super::setPriority(client, extents, extentsCount, priority));
}

UInt64
ZFSDataset::getPreferredBlockSize() const
{
	DLOGFUNC();
	//return (DEV_BSIZE);
	return (super::getPreferredBlockSize());
}

UInt64
ZFSDataset::getSize() const
{
	DLOGFUNC();
	return (super::getSize());
}

UInt64
ZFSDataset::getBase() const
{
	DLOGFUNC();
	return (super::getBase());
}

bool
ZFSDataset::isEjectable() const
{
	DLOGFUNC();
	return (super::isEjectable());
}

bool
ZFSDataset::isFormatted() const
{
	DLOGFUNC();
	return (super::isFormatted());
}

bool
ZFSDataset::isWhole() const
{
	DLOGFUNC();
	return (super::isWhole());
}

bool
ZFSDataset::isWritable() const
{
	DLOGFUNC();
	return (super::isWritable());
}

const char *
ZFSDataset::getContent() const
{
	DLOGFUNC();
	return (super::getContent());
}

const char *
ZFSDataset::getContentHint() const
{
	DLOGFUNC();
	return (super::getContentHint());
}

IOMediaAttributeMask
ZFSDataset::getAttributes() const
{
	DLOGFUNC();
	return (super::getAttributes());
}

bool
ZFSDataset::setDatasetName(const char *name)
{
	char *newname;
	size_t len;

	if (!name || name[0] == '\0') {
		dprintf("%s missing name\n", __func__);
		return (false);
	}

	/* Length of IOMedia name plus null terminator */
	len = (strlen(kZFSIOMediaPrefix) + strlen(name) +
	    strlen(kZFSIOMediaSuffix) + 1);
	//len = strlen("ZFS ") + strlen(name) + strlen(" Media") + 1;

	newname = (char *)kmem_alloc(len, KM_SLEEP);
	if (!newname) {
		dprintf("%s alloc failed\n", __func__);
		return (false);
	}

	bzero(newname, len);
	snprintf(newname, len, "%s%s%s", kZFSIOMediaPrefix,
	    name, kZFSIOMediaSuffix);
	if (strlen(newname) < 1) {
		dprintf("%s invalid newname for %s\n", __func__, name);
		IOSleep(1000);
		kmem_free(newname, len);
		return (false);
	}
	setName(newname);

	setProperty(kZFSDatasetNameKey, name);

	kmem_free(newname, len);

	return (true);
}
