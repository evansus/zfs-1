
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>
#include <sys/zfs_boot.h>
#include <sys/spa_impl.h>

#include <sys/ZFSPool.h>
#include <sys/zvolIO.h>

#include <IOKit/IOKitKeys.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOStorageProtocolCharacteristics.h>

/*
 * ZVOL Device
 */

#if defined(DEBUG) || defined(ZFS_DEBUG)
#ifdef	dprintf
#undef	dprintf
#endif
#define	dprintf(fmt, ...) do {							\
	IOLog("zvolIO %s " fmt "\n", __func__, ##__VA_ARGS__);	\
_NOTE(CONSTCOND) } while (0)
#else
#ifndef dprintf
#define	dprintf(fmt, ...)	do { } while (0);
#endif
#endif /* if DEBUG or ZFS_DEBUG */

//#define dprintf IOLog

// Define the superclass
#define	super IOBlockStorageDevice

#define	ZVOL_BSIZE	DEV_BSIZE

static const char* ZVOL_PRODUCT_NAME_PREFIX = "ZVOL ";

/* Wrapper for zvol_state pointer to IOKit device */
typedef struct zvol_iokit {
	net_lundman_zfs_zvol_device *dev;
} zvol_iokit_t;

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol_device, IOBlockStorageDevice)

bool
net_lundman_zfs_zvol_device::init(zvol_state_t *c_zv,
    OSDictionary *properties)
{
	zvol_iokit_t *iokitdev;

	dprintf("zvolIO_device:init\n");

	if (!c_zv || c_zv->zv_iokitdev != NULL) {
		dprintf("zvol %s invalid c_zv\n", __func__);
		return (false);
	}

	if ((iokitdev = (zvol_iokit_t *)kmem_alloc(sizeof (zvol_iokit_t),
	    KM_SLEEP)) == NULL) {
		printf("zvol %s wrapper alloc failed\n", __func__);
		return (false);
	}

	if (super::init(properties) == false) {
		printf("zvol %s super init failed\n", __func__);
		kmem_free(iokitdev, sizeof (zvol_iokit_t));
		return (false);
	}

	/* Store reference to zvol_state_t in the iokitdev */
	zv = c_zv;
	/* Store reference to iokitdev in zvol_state_t */
	iokitdev->dev = this;

	/* Assign to zv once completely initialized */
	zv->zv_iokitdev = iokitdev;

	/* Apply the name from the full dataset path */
	if (strlen(zv->zv_name) != 0) {
		setName(zv->zv_name);
	}

	return (true);
}

bool
net_lundman_zfs_zvol_device::attach(IOService* provider)
{
	OSDictionary *protocolCharacteristics = 0;
	OSDictionary *deviceCharacteristics = 0;
	OSDictionary *storageFeatures = 0;
	OSBoolean *unmapFeature = 0;
	const OSSymbol *propSymbol = 0;
	OSString *dataString = 0;
	OSNumber *dataNumber = 0;

	char product_name[strlen(ZVOL_PRODUCT_NAME_PREFIX) + MAXPATHLEN + 1];

	if (!provider) {
		dprintf("ZVOL attach missing provider\n");
		return (false);
	}

	if (super::attach(provider) == false)
		return (false);

	/*
	 * We want to set some additional properties for ZVOLs, in
	 * particular, "Virtual Device", and type "File"
	 * (or is Internal better?)
	 *
	 * Finally "Generic" type.
	 *
	 * These properties are defined in *protocol* characteristics
	 */

	protocolCharacteristics = OSDictionary::withCapacity(3);

	if (!protocolCharacteristics) {
		IOLog("failed to create dict for protocolCharacteristics.\n");
		return (true);
	}

	propSymbol = OSSymbol::withCString(
	    kIOPropertyPhysicalInterconnectTypeVirtual);

	if (!propSymbol) {
		IOLog("could not create interconnect type string\n");
		return (true);
	}
	protocolCharacteristics->setObject(
	    kIOPropertyPhysicalInterconnectTypeKey, propSymbol);

	propSymbol->release();
	propSymbol = 0;

	propSymbol = OSSymbol::withCString(kIOPropertyInterconnectFileKey);
	if (!propSymbol) {
		IOLog("could not create interconnect location string\n");
		return (true);
	}
	protocolCharacteristics->setObject(
	    kIOPropertyPhysicalInterconnectLocationKey, propSymbol);

	propSymbol->release();
	propSymbol = 0;

	setProperty(kIOPropertyProtocolCharacteristicsKey,
	    protocolCharacteristics);

	protocolCharacteristics->release();
	protocolCharacteristics = 0;

	/*
	 * We want to set some additional properties for ZVOLs, in
	 * particular, physical block size (volblocksize) of the
	 * underlying ZVOL, and 'logical' block size presented by
	 * the virtual disk. Also set physical bytes per sector.
	 *
	 * These properties are defined in *device* characteristics
	 */

	deviceCharacteristics = OSDictionary::withCapacity(3);

	if (!deviceCharacteristics) {
		IOLog("failed to create dict for deviceCharacteristics.\n");
		return (true);
	}

	/* Set this device to be an SSD, for priority and VM paging */
	propSymbol = OSSymbol::withCString(
	    kIOPropertyMediumTypeSolidStateKey);
	if (!propSymbol) {
		IOLog("could not create medium type string\n");
		return (true);
	}
	deviceCharacteristics->setObject(kIOPropertyMediumTypeKey,
	    propSymbol);

	propSymbol->release();
	propSymbol = 0;

	/* Set logical block size to ZVOL_BSIZE (512b) */
	dataNumber =	OSNumber::withNumber(ZVOL_BSIZE,
	    8 * sizeof (ZVOL_BSIZE));

	deviceCharacteristics->setObject(kIOPropertyLogicalBlockSizeKey,
	    dataNumber);

	dprintf("logicalBlockSize %llu\n",
	    dataNumber->unsigned64BitValue());

	dataNumber->release();
	dataNumber	= 0;

	/* Set physical block size to match volblocksize property */
	dataNumber =	OSNumber::withNumber(zv->zv_volblocksize,
	    8 * sizeof (zv->zv_volblocksize));

	deviceCharacteristics->setObject(kIOPropertyPhysicalBlockSizeKey,
	    dataNumber);

	dprintf("physicalBlockSize %llu\n",
	    dataNumber->unsigned64BitValue());

	dataNumber->release();
	dataNumber	= 0;

	/* Set physical bytes per sector to match volblocksize property */
	dataNumber =	OSNumber::withNumber((uint64_t)(zv->zv_volblocksize),
	    8 * sizeof (uint64_t));

	deviceCharacteristics->setObject(kIOPropertyBytesPerPhysicalSectorKey,
	    dataNumber);

	dprintf("physicalBytesPerSector %llu\n",
	    dataNumber->unsigned64BitValue());

	dataNumber->release();
	dataNumber	= 0;

	/* Publish the Device / Media name */
	(void)snprintf(product_name, sizeof(product_name), "%s%s",
	    ZVOL_PRODUCT_NAME_PREFIX, zv->zv_name);
	dataString = OSString::withCString(product_name);
	deviceCharacteristics->setObject(kIOPropertyProductNameKey, dataString);
	dataString->release();
	dataString = 0;

	/* Apply these characteristics */
	setProperty(kIOPropertyDeviceCharacteristicsKey,
	    deviceCharacteristics);

	deviceCharacteristics->release();
	deviceCharacteristics	= 0;

	/*
	 * ZVOL unmap support
	 *
	 * These properties are defined in IOStorageFeatures
	 */

	storageFeatures =	OSDictionary::withCapacity(1);
	if (!storageFeatures) {
		IOLog("failed to create dictionary for storageFeatures.\n");
		return (true);
	}

	/* Set unmap feature */
	unmapFeature =	OSBoolean::withBoolean(true);
	storageFeatures->setObject(kIOStorageFeatureUnmap, unmapFeature);
	unmapFeature->release();
	unmapFeature	= 0;

	/* Apply these storage features */
	setProperty(kIOStorageFeaturesKey, storageFeatures);
	storageFeatures->release();
	storageFeatures	= 0;


	/*
	 * Set transfer limits:
	 *
	 *  Maximum transfer size (bytes)
	 *  Maximum transfer block count
	 *  Maximum transfer block size (bytes)
	 *  Maximum transfer segment count
	 *  Maximum transfer segment size (bytes)
	 *  Minimum transfer segment size (bytes)
	 *
	 *  We will need to establish safe defaults for all / per volblocksize
	 *
	 *  Example: setProperty(kIOMinimumSegmentAlignmentByteCountKey, 1, 1);
	 */

	/*
	 * Finally "Generic" type, set as a device property. Tried setting this
	 * to the string "ZVOL" however the OS does not recognize it as a block
	 * storage device. This would probably be possible by extending the
	 * IOBlockStorage Device / Driver relationship.
	 */

	setProperty(kIOBlockStorageDeviceTypeKey,
	    kIOBlockStorageDeviceTypeGeneric);

	return (true);
}

int
net_lundman_zfs_zvol_device::renameDevice(void)
{
	OSDictionary *deviceDict;
	OSString *nameStr;
	char *newstr;
	int len;

	/* Length of string and null terminating character */
	len = strlen(ZVOL_PRODUCT_NAME_PREFIX) + strlen(zv->zv_name) + 1;
	newstr = (char *)kmem_alloc(len, KM_SLEEP);
	if (!newstr) {
		dprintf("%s string alloc failed\n", __func__);
		return (ENOMEM);
	}

	/* Append prefix and dsl name */
	snprintf(newstr, len, "%s%s", ZVOL_PRODUCT_NAME_PREFIX, zv->zv_name);
	nameStr = OSString::withCString(newstr);
	kmem_free(newstr, len);

	if (!nameStr) {
		dprintf("%s couldn't allocate name string\n", __func__);
		return (ENOMEM);
	}

	/* Fetch current device characteristics dictionary */
	deviceDict = OSDynamicCast(OSDictionary,
	    getProperty(kIOPropertyDeviceCharacteristicsKey));
	if (!deviceDict || (deviceDict =
	    OSDictionary::withDictionary(deviceDict)) == NULL) {
		dprintf("couldn't clone device characteristics\n");
		/* Allocate new dict */
		if (!deviceDict &&
		    (deviceDict = OSDictionary::withCapacity(1)) == NULL) {
			dprintf("%s OSDictionary alloc failed\n", __func__);
			nameStr->release();
			return (ENOMEM);
		}

	}

	/* Add or replace the product name */
	if (deviceDict->setObject(kIOPropertyProductNameKey,
	    nameStr) == false) {
		dprintf("%s couldn't set product name\n", __func__);
		nameStr->release();
		deviceDict->release();
		return (ENXIO);
	}
	nameStr->release();
	nameStr = 0;

	/* Set IORegistry property */
	if (setProperty(kIOPropertyDeviceCharacteristicsKey,
	    deviceDict) == false) {
		dprintf("%s couldn't set IORegistry property\n", __func__);
		deviceDict->release();
		return (ENXIO);
	}
	deviceDict->release();
	deviceDict = 0;

	/* Apply the name from the full dataset path */
	setName(zv->zv_name);

	return (0);
}

int
net_lundman_zfs_zvol_device::offlineDevice(void)
{
	IOService *client;

	if ((client = this->getClient()) == NULL) {
		return (ENOENT);
	}

	/* Ask IOBlockStorageDevice to offline media */
	if (client->message(kIOMessageMediaStateHasChanged,
	    this, (void *)kIOMediaStateOffline) != kIOReturnSuccess) {
		dprintf("%s failed\n", __func__);
		return (ENXIO);
	}

	return (0);
}

int
net_lundman_zfs_zvol_device::onlineDevice(void)
{
	IOService *client;

	if ((client = this->getClient()) == NULL) {
		return (ENOENT);
	}

	/* Ask IOBlockStorageDevice to online media */
	if (client->message(kIOMessageMediaStateHasChanged,
	    this, (void *)kIOMediaStateOnline) != kIOReturnSuccess) {
		dprintf("%s failed\n", __func__);
		return (ENXIO);
	}

	return (0);
}

int
net_lundman_zfs_zvol_device::refreshDevice(void)
{
	IOService *client;

	if ((client = this->getClient()) == NULL) {
		return (ENOENT);
	}

	/* Ask IOBlockStorageDevice to reset the media params */
	if (client->message(kIOMessageMediaParametersHaveChanged,
	    this) != kIOReturnSuccess) {
		dprintf("%s failed\n", __func__);
		return (ENXIO);
	}

	return (0);
}

int
net_lundman_zfs_zvol_device::getBSDName(void)
{
	IORegistryEntry *ioregdevice = 0;
	OSObject *bsdnameosobj = 0;
	OSString* bsdnameosstr = 0;

	ioregdevice = OSDynamicCast(IORegistryEntry, this);

	if (!ioregdevice)
		return (-1);

	bsdnameosobj = ioregdevice->getProperty(kIOBSDNameKey,
	    gIOServicePlane, kIORegistryIterateRecursively);

	if (!bsdnameosobj)
		return (-1);

	bsdnameosstr = OSDynamicCast(OSString, bsdnameosobj);

	IOLog("zvol: bsd name is '%s'\n",
	    bsdnameosstr->getCStringNoCopy());

	if (!zv)
		return (-1);

	zv->zv_bsdname[0] = 'r'; // for 'rdiskX'.
	strlcpy(&zv->zv_bsdname[1],
	    bsdnameosstr->getCStringNoCopy(),
	    sizeof (zv->zv_bsdname)-1);
	/*
	 * IOLog("name assigned '%s'\n", zv->zv_bsdname);
	 */

	return (0);
}

void
net_lundman_zfs_zvol_device::detach(IOService *provider)
{
	super::detach(provider);
}

extern boolean_t spa_exporting_vdevs;

bool
net_lundman_zfs_zvol_device::handleOpen(IOService *client,
    IOOptionBits options, void *argument)
{
#if 0
	IOStorageAccess access = (IOStorageAccess)(uint64_t)argument;
#endif
	bool ret = false;

	dprintf("open: options %x\n", options);

	if (super::handleOpen(client, options, argument) == false)
		return (false);

    spa_exporting_vdevs = B_TRUE;

#if 0
	/*
	 * It was the hope that openHandle would indicate the type of open
	 * required such that we can set FREAD/FWRITE/ZVOL_EXCL as needed, but
	 * alas, "access" is always 0 here.
	 */
	switch (access) {

		case kIOStorageAccessReader:
			//IOLog("handleOpen: readOnly\n");
			zv->zv_openflags = FREAD;
			zvol_open_impl(zv, FREAD /* ZVOL_EXCL */, 0, NULL);
			break;

		case kIOStorageAccessReaderWriter:
			// IOLog("handleOpen: options %04x\n", options);
			break;

		default:
			// IOLog("handleOpen with unknown access %04lu\n",
			//	access);
			zv->zv_openflags = FWRITE;
	}
#endif

	zv->zv_openflags = FWRITE | ZVOL_EXCL;
	if (zvol_open_impl(zv, zv->zv_openflags, 0, NULL) == 0) {
		ret = true;
	} else {
		zv->zv_openflags = FREAD;
		if (zvol_open_impl(zv, FREAD /* ZVOL_EXCL */, 0, NULL) == 0)
			ret = true;
	}

    spa_exporting_vdevs = B_FALSE;

	dprintf("Open %s\n", (ret ? "done" : "failed"));

	if (ret == false) {
		super::handleClose(client, options);
	}
	return (ret);
}



void
net_lundman_zfs_zvol_device::handleClose(IOService *client,
    IOOptionBits options)
{
	super::handleClose(client, options);

	// IOLog("handleClose\n");
    spa_exporting_vdevs = B_TRUE;
	zvol_close_impl(zv, zv->zv_openflags, 0, NULL);
    spa_exporting_vdevs = B_FALSE;

}

IOReturn
net_lundman_zfs_zvol_device::doAsyncReadWrite(
    IOMemoryDescriptor *buffer, UInt64 block, UInt64 nblks,
    IOStorageAttributes *attributes, IOStorageCompletion *completion)
{
	IODirection direction;
	IOByteCount actualByteCount;
#if 0
	struct iomem *iomem = 0;
	// struct io_context *context = 0;
#else
	/*
	 * XXX Until we implement async IO, an on-stack struct is
	 * fine. At that point we can embed the buffer in an IO
	 * context struct with the completion callback, plus list
	 * pointers to track inflight/completed IOs.
	 */
	struct iomem iomem;
	iomem.buf = NULL;
#endif

	// Return errors for incoming I/O if we have been terminated.
	if (isInactive() == true) {
		dprintf("asyncReadWrite notActive fail\n");
		return (kIOReturnNotAttached);
	}
	// These variables are set in zvol_first_open(), which should have been
	// called already.
	if (!zv->zv_objset || !zv->zv_dbuf) {
		dprintf("asyncReadWrite no objset nor dbuf\n");
		return (kIOReturnNotAttached);
	}

	// Ensure the start block is within the disk capacity.
	if ((block)*(ZVOL_BSIZE) >= zv->zv_volsize) {
		dprintf("asyncReadWrite start block outside volume\n");
		return (kIOReturnBadArgument);
	}

	// Shorten the read, if beyond the end
	if (((block + nblks)*(ZVOL_BSIZE)) > zv->zv_volsize) {
		dprintf("asyncReadWrite block shortening needed\n");
		return (kIOReturnBadArgument);
	}

	// Get the buffer direction, whether this is a read or a write.
	direction = buffer->getDirection();
	if ((direction != kIODirectionIn) && (direction != kIODirectionOut)) {
		dprintf("asyncReadWrite kooky direction\n");
		return (kIOReturnBadArgument);
	}

	dprintf("%s offset @block %llu numblocks %llu: blksz %u\n",
	    direction == kIODirectionIn ? "Read" : "Write",
	    block, nblks, (ZVOL_BSIZE));

	/* Perform the read or write operation through the transport driver. */
	actualByteCount = (nblks*(ZVOL_BSIZE));

#if 0
	if ((iomem = (struct iomem *)kmem_alloc(sizeof (struct iomem),
	    KM_SLEEP)) == NULL) {
		dprintf("%s allocation failed\n", __func__);
		(completion->action)(completion->target, completion->parameter,
		    kIOReturnSuccess, actualByteCount);
		return (kIOReturnSuccess);
	}
	iomem->buf = buffer;
#else
	iomem.buf = buffer;
#endif

	/* Make sure we don't go away while the command is being executed */
	/* Open should be holding a retain */
	//retain();
	//m_provider->retain();

	if (direction == kIODirectionIn) {

#if 0
		if (zvol_read_iokit(zv, (block*(ZVOL_BSIZE)),
		    actualByteCount, iomem)) {
#else
		if (zvol_read_iokit(zv, (block*(ZVOL_BSIZE)),
		    actualByteCount, &iomem)) {
#endif

			actualByteCount = 0;
		}

	} else {

#if 0
		if (zvol_write_iokit(zv, (block*(ZVOL_BSIZE)),
		    actualByteCount, iomem)) {
#else
		if (zvol_write_iokit(zv, (block*(ZVOL_BSIZE)),
		    actualByteCount, &iomem)) {
#endif
			actualByteCount = 0;
		}

	}

	/* Open should be holding a retain */
	//m_provider->release();
	//release();

#if 0
	/* If async, this would happen in io_done() */
	kmem_free(iomem, sizeof (struct iomem));
#else
	iomem.buf = NULL; // overkill
#endif

	if (actualByteCount != nblks*(ZVOL_BSIZE))
		dprintf("Read/Write operation failed\n");

	// Call the completion function.
	(completion->action)(completion->target, completion->parameter,
	    kIOReturnSuccess, actualByteCount);
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doDiscard(UInt64 block, UInt64 nblks)
{
	dprintf("doDiscard called with block, nblks (%llu, %llu)\n",
	    block, nblks);
	uint64_t bytes		= 0;
	uint64_t off		= 0;

	/* Convert block/nblks to offset/bytes */
	off =	block * ZVOL_BSIZE;
	bytes =	nblks * ZVOL_BSIZE;
	dprintf("calling zvol_unmap with offset, bytes (%llu, %llu)\n",
	    off, bytes);

	if (zvol_unmap(zv, off, bytes) == 0)
		return (kIOReturnSuccess);
	else
		return (kIOReturnError);
}


IOReturn
net_lundman_zfs_zvol_device::doUnmap(IOBlockStorageDeviceExtent *extents,
    UInt32 extentsCount, UInt32 options = 0)
{
	UInt32 i = 0;
	IOReturn result;

	dprintf("doUnmap called with (%u) extents and options (%u)\n",
	    (uint32_t)extentsCount, (uint32_t)options);

	if (options > 0 || !extents) {
		return (kIOReturnUnsupported);
	}

	for (i = 0; i < extentsCount; i++) {

		result = doDiscard(extents[i].blockStart,
		    extents[i].blockCount);

		if (result != kIOReturnSuccess) {
			return (result);
		}
	}

	return (kIOReturnSuccess);
}

UInt32
net_lundman_zfs_zvol_device::doGetFormatCapacities(UInt64* capacities,
    UInt32 capacitiesMaxCount) const
{
	dprintf("formatCap\n");

	/*
	 * Ensure that the array is sufficient to hold all our formats
	 * (we require one element).
	 */
	if ((capacities != NULL) && (capacitiesMaxCount < 1))
		return (0);
		/* Error, return an array size of 0. */

	/*
	 * The caller may provide a NULL array if it wishes to query the number
	 * of formats that we support.
	 */
	if (capacities != NULL)
		capacities[0] = zv->zv_volsize;

	dprintf("returning capacity[0] size %llu\n", zv->zv_volsize);

	return (1);
}

char *
net_lundman_zfs_zvol_device::getProductString(void)
{
	dprintf("getProduct %p\n", zv);

	if (zv) return (zv->zv_name);

	return ((char *)"ZVolume");
}

IOReturn
net_lundman_zfs_zvol_device::reportBlockSize(UInt64 *blockSize)
{
	dprintf("reportBlockSize %llu\n", *blockSize);

	if (blockSize) *blockSize = (ZVOL_BSIZE);

	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportMaxValidBlock(UInt64 *maxBlock)
{
	dprintf("reportMaxValidBlock %llu\n", *maxBlock);

	if (maxBlock) *maxBlock = ((zv->zv_volsize / (ZVOL_BSIZE)) - 1);

	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportMediaState(bool *mediaPresent,
    bool *changedState)
{
	dprintf("reportMediaState\n");
	if (mediaPresent) *mediaPresent = true;
	if (changedState) *changedState = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportPollRequirements(bool *pollRequired,
    bool *pollIsExpensive)
{
	dprintf("reportPollReq\n");
	if (pollRequired) *pollRequired = false;
	if (pollIsExpensive) *pollIsExpensive = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportRemovability(bool *isRemovable)
{
	dprintf("reportRemova\n");
	if (isRemovable) *isRemovable = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doEjectMedia(void)
{
	dprintf("ejectMedia\n");
/* XXX */
	// Only 10.6 needs special work to eject
	//if ((version_major == 10) && (version_minor == 8))
	//	destroyBlockStorageDevice(zvol);
	//}

	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doFormatMedia(UInt64 byteCapacity)
{
	dprintf("doFormat\n");
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doLockUnlockMedia(bool doLock)
{
	dprintf("doLockUnlock\n");
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doSynchronizeCache(void)
{
	dprintf("doSync\n");
	if (zv && zv->zv_zilog) {
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	}
	return (kIOReturnSuccess);
}

char *
net_lundman_zfs_zvol_device::getVendorString(void)
{
	dprintf("getVendor\n");
	return ((char *)"ZVOL");
}

char *
net_lundman_zfs_zvol_device::getRevisionString(void)
{
	dprintf("getRevision\n");
	return ((char *)ZFS_META_VERSION);
}

char *
net_lundman_zfs_zvol_device::getAdditionalDeviceInfoString(void)
{
	dprintf("getAdditional\n");
	return ((char *)"ZFS Volume");
}

IOReturn
net_lundman_zfs_zvol_device::reportEjectability(bool *isEjectable)
{
	dprintf("reportEjecta\n");
	/*
	 * Which do we prefer? If you eject it, you can't get volume back until
	 * you import it again.
	 */

	if (isEjectable) *isEjectable = false;
	return (kIOReturnSuccess);
}

/* XXX deprecated function */
IOReturn
net_lundman_zfs_zvol_device::reportLockability(bool *isLockable)
{
	dprintf("reportLocka\n");
	if (isLockable) *isLockable = true;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportWriteProtection(bool *isWriteProtected)
{
	dprintf("reportWritePro: %d\n", *isWriteProtected);

	if (!isWriteProtected) return (kIOReturnSuccess);

	if (zv && (zv->zv_flags & ZVOL_RDONLY))
		*isWriteProtected = true;
	else
		*isWriteProtected = false;

	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::getWriteCacheState(bool *enabled)
{
	dprintf("getCacheState\n");
	if (enabled) *enabled = true;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::setWriteCacheState(bool enabled)
{
	dprintf("setWriteCache\n");
	return (kIOReturnSuccess);
}

extern "C" {

/* C interfaces */
int
zvolCreateNewDevice(zvol_state_t *zv)
{
	net_lundman_zfs_zvol_device *zvol;
	ZFSPool *pool_proxy;
	spa_t *spa;
	dprintf("%s\n", __func__);

	/* We must have a valid zvol_state_t */
	if (!zv || !zv->zv_objset) {
		dprintf("%s missing zv or objset\n", __func__);
		return (EINVAL);
	}

	/* We need the spa to get the pool proxy */
	if ((spa = dmu_objset_spa(zv->zv_objset)) == NULL) {
		dprintf("%s couldn't get spa\n", __func__);
		return (EINVAL);
	}
	if (spa->spa_iokit_proxy == NULL ||
	    (pool_proxy = spa->spa_iokit_proxy->proxy) == NULL) {
		dprintf("%s missing IOKit pool proxy\n", __func__);
		return (EINVAL);
	}

	zvol = new net_lundman_zfs_zvol_device;

	/* Validate creation, initialize and attach */
	if (!zvol || zvol->init(zv) == false ||
	    zvol->attach(pool_proxy) == false) {
		dprintf("%s device creation failed\n", __func__);
		if (zvol) zvol->release();
		return (ENOMEM);
	}
	/* Start the service */
	if (zvol->start(pool_proxy) == false) {
		dprintf("%s device start failed\n", __func__);
		zvol->detach(pool_proxy);
		zvol->release();
		return (ENXIO);
	}

	/* Open pool_proxy provider */
	if (pool_proxy->open(zvol) == false) {
		dprintf("%s open provider failed\n", __func__);
		zvol->stop(pool_proxy);
		zvol->detach(pool_proxy);
		zvol->release();
		return (ENXIO);
	}
	/* Is retained by provider */
	zvol->release();
	zvol = 0;

	return (0);
}

int
zvolRegisterDevice(zvol_state_t *zv)
{
	net_lundman_zfs_zvol_device *zvol;
	OSDictionary *matching;
	IOService *service = 0;
	IOMedia *media = 0;
	OSString *nameStr = 0, *bsdName = 0;
	uint64_t timeout = (5ULL * kSecondScale);
	bool ret = false;

	if (!zv || !zv->zv_iokitdev || strnlen(zv->zv_name, 1) == 0) {
		dprintf("%s missing zv, iokitdev, or name\n", __func__);
		return (EINVAL);
	}

	if ((zvol = zv->zv_iokitdev->dev) == NULL) {
		dprintf("%s couldn't get zvol device\n", __func__);
		return (EINVAL);
	}

	/* Create matching string and dictionary */
	{
		char str[MAXNAMELEN];
		snprintf(str, MAXNAMELEN, "%s %s Media",
		    zvol->getVendorString(), zv->zv_name);
		if ((nameStr = OSString::withCString(str)) == NULL) {
			dprintf("%s problem with name string\n", __func__);
			return (ENOMEM);
		}
	}
	matching = IOService::serviceMatching("IOMedia");
	if (!matching || !matching->setObject(gIONameMatchKey, nameStr)) {
		dprintf("%s couldn't get matching dictionary\n", __func__);
		return (ENOMEM);
	}

	/* Register device for service matching */
	zvol->registerService(kIOServiceAsynchronous);

	/* Wait for upper layer BSD client */
	dprintf("%s waiting for IOMedia\n", __func__);
	/* Wait for up to 5 seconds */
	service = IOService::waitForMatchingService(matching, timeout);
	dprintf("%s %s service\n", __func__, (service ? "got" : "no"));

	if (!service) {
		dprintf("%s couldn't get matching service\n", __func__);
		return (false);
	}

	dprintf("%s casting to IOMedia\n", __func__);
	media = OSDynamicCast(IOMedia, service);

	if (!media) {
		dprintf("%s no IOMedia\n", __func__);
		return (false);
	}

	dprintf("%s getting IOBSDNameKey\n", __func__);
	bsdName = OSDynamicCast(OSString,
	    media->getProperty(kIOBSDNameKey));

	if (bsdName) {
		const char *str = bsdName->getCStringNoCopy();
		dprintf("%s Got bsd name [%s]\n",
		    __func__, str);
		zv->zv_bsdname[0] = 'r';
		snprintf(zv->zv_bsdname+1, sizeof(zv->zv_bsdname)-1,
		    "%s", str);
		dprintf("%s zvol bsdname set to %s\n", __func__,
		    zv->zv_bsdname);
		zvol_add_symlink(zv, zv->zv_bsdname+1,
		    zv->zv_bsdname);
		ret = true;
	} else {
		dprintf("%s couldn't get BSD Name\n", __func__);
	}

	/* Release retain held by waitForMatchingService */
	service->release();

	return (ret);
}

/* Struct passed in will be freed before returning */
int
zvolRemoveDevice(zvol_iokit_t *iokitdev)
{
	net_lundman_zfs_zvol_device *zvol;
	dprintf("%s\n", __func__);

	if (!iokitdev) {
		dprintf("%s missing argument\n", __func__);
		return (EINVAL);
	}

	zvol = iokitdev->dev;
	/* Free the wrapper struct */
	kmem_free(iokitdev, sizeof (zvol_iokit_t));

	if (zvol == NULL) {
		dprintf("%s couldn't get IOKit handle\n", __func__);
		return (ENXIO);
	}

#if 0
	IOService *provider;
	provider = zvol->getProvider();

	/* Ask the IOBlockStorageDriver to decommission media */
	IOReturn ret;
	if ((ret = zvol->message(kIOMessageServiceIsRequestingClose,
	    provider)) != kIOReturnSuccess) {
		dprintf("%s media close failed %d\n", __func__, ret);
	}
#endif

	/* Terminate */
	if (zvol->terminate(kIOServiceTerminate|
	    kIOServiceRequired) == false) {
		IOLog("%s terminate failed\n", __func__);
	}
	//zvol->release();
	zvol = 0;

	return (0);
}

/* Called with zv->zv_name already updated */
int
zvolRenameDevice(zvol_state_t *zv)
{
	net_lundman_zfs_zvol_device *zvol;
	int error;

	if (!zv || strnlen(zv->zv_name, 1) == 0) {
		dprintf("%s missing argument\n", __func__);
		return (EINVAL);
	}

	if ((zvol = zv->zv_iokitdev->dev) == NULL) {
		dprintf("%s couldn't get zvol device\n", __func__);
		return (EINVAL);
	}

	/* Set IORegistry name and property */
	if ((error = zvol->renameDevice()) != 0) {
		dprintf("%s renameDevice error %d\n", __func__, error);
		return (error);
	}

	/*
	 * XXX This works, but if there is a volume mounted on
	 * the zvol at the time it is uncleanly ejected.
	 * We just need to add diskutil unmount to `zfs rename`,
	 * like zpool export.
	 */
	/* Inform clients of this device that name has changed */
	if (zvol->offlineDevice() != 0 ||
	    zvol->onlineDevice() != 0) {
		dprintf("%s media reset failed\n", __func__);
		return (ENXIO);
	}

	return (0);
}

/* Called with zvol volsize already updated */
int
zvolSetVolsize(zvol_state_t *zv)
{
	net_lundman_zfs_zvol_device *zvol;
	int error;

	dprintf("%s\n", __func__);

	if (!zv || !zv->zv_iokitdev) {
		dprintf("%s invalid zvol\n", __func__);
		return (EINVAL);
	}

	/* Cast to correct type */
	if ((zvol = zv->zv_iokitdev->dev) == NULL) {
		dprintf("%s couldn't cast IOKit handle\n", __func__);
		return (ENXIO);
	}

	/*
	 * XXX This works fine, even if volume is mounted,
	 * but only tested expanding the zvol and only with
	 * GPT/APM/MBR partition map (not volume on whole-zvol).
	 */
	/* Inform clients of this device that size has changed */
	if ((error = zvol->refreshDevice()) != 0) {
		dprintf("%s refreshDevice error %d\n", __func__, error);
		return (error);
	}

	return (0);
}

uint64_t
zvolIO_kit_read(struct iomem *iomem, uint64_t offset,
    char *address, uint64_t len)
{
	IOByteCount done;
	//IOLog("zvolIO_kit_read offset %p count %llx to offset %llx\n",
	//    address, len, offset);
	ASSERT (iomem && address && len > 0);

	done = iomem->buf->writeBytes(offset, (void *)address, len);

	return (done);
}

uint64_t
zvolIO_kit_write(struct iomem *iomem, uint64_t offset,
    char *address, uint64_t len)
{
	IOByteCount done;
	//IOLog("zvolIO_kit_write offset %p count %llx to offset %llx\n",
	//    address, len, offset);
	ASSERT (iomem && address && len > 0);

	done = iomem->buf->readBytes(offset, (void *)address, len);

	return (done);
}

} /* extern "C" */
