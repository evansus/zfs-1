/*
 * ZFSDataset - proxy disk for legacy and com.apple.devicenode mounts.
 */

#ifndef ZFSDATASET_H_INCLUDED
#define	ZFSDATASET_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * inout buffer should be set to the bsd name when called, and
 * will be set to the osname on success
 */
int zfs_dataset_proxy_get_osname(const char *in, char *out, int len);

int spa_iokit_dataset_proxy_create(const char *osname);


#ifdef __cplusplus
} /* extern "C" */

#include <IOKit/storage/IOMedia.h>

#ifdef super
#undef super
#endif
#define super IOMedia

/* XXX Should be UUID */
#define	kZFSContentHint		"ZFS"

#define	kZFSIOMediaPrefix	"ZFS "
#define	kZFSIOMediaSuffix	" Media"
#define	kZFSDatasetNameKey	"ZFS Dataset"

class ZFSDataset : public IOMedia
{
	OSDeclareDefaultStructors(ZFSDataset)
public:
#if 0
	/* XXX Only for debug tracing */
	virtual bool open(IOService *client,
	    IOOptionBits options, IOStorageAccess access = 0);
	virtual bool isOpen(const IOService *forClient = 0) const;
	virtual void close(IOService *client,
	    IOOptionBits options);

	virtual bool handleOpen(IOService *client,
	    IOOptionBits options, void *access);
	virtual bool handleIsOpen(const IOService *client) const;
	virtual void handleClose(IOService *client,
	    IOOptionBits options);
#endif

	virtual bool attach(IOService *provider);
	virtual void detach(IOService *provider);

	virtual bool start(IOService *provider);
	virtual void stop(IOService *provider);

	virtual bool init(UInt64 base, UInt64 size,
	    UInt64 preferredBlockSize,
	    IOMediaAttributeMask attributes,
	    bool isWhole, bool isWritable,
	    const char *contentHint = 0,
	    OSDictionary *properties = 0);
	virtual void free();

	static ZFSDataset * withDatasetName(const char *name);

	virtual void read(IOService *client,
	    UInt64 byteStart, IOMemoryDescriptor *buffer,
	    IOStorageAttributes *attributes,
	    IOStorageCompletion *completion);
	virtual void write(IOService *client,
	    UInt64 byteStart, IOMemoryDescriptor *buffer,
	    IOStorageAttributes *attributes,
	    IOStorageCompletion *completion);

	virtual IOReturn synchronize(IOService *client,
	    UInt64 byteStart, UInt64 byteCount,
	    IOStorageSynchronizeOptions options = 0);
	virtual IOReturn unmap(IOService *client,
	    IOStorageExtent *extents, UInt32 extentsCount,
	    IOStorageUnmapOptions options = 0);

	virtual IOStorage *copyPhysicalExtent(IOService *client,
	    UInt64 *byteStart, UInt64 *byteCount);

	virtual void unlockPhysicalExtents(IOService *client);

	virtual IOReturn setPriority(IOService *client,
	    IOStorageExtent *extents, UInt32 extentsCount,
	    IOStoragePriority priority);

	virtual UInt64 getPreferredBlockSize() const;
	virtual UInt64 getSize() const;
	virtual UInt64 getBase() const;

	virtual bool isEjectable() const;
	virtual bool isFormatted() const;
	virtual bool isWhole() const;
	virtual bool isWritable() const;

	virtual const char * getContent() const;
	virtual const char * getContentHint() const;
	virtual IOMediaAttributeMask getAttributes() const;

protected:
private:
	bool setDatasetName(const char *);


};

#endif /* __cplusplus */

#endif /* ZFSDATASET_H_INCLUDED */
